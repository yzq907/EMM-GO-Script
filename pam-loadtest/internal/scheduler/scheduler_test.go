package scheduler

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"pam-loadtest/internal/config"
	"pam-loadtest/internal/session"
)

func jobs(n int) []config.Job {
	out := make([]config.Job, n)
	for i := range out {
		out[i] = config.Job{ID: i + 1, Protocol: config.SSH}
	}
	return out
}

type startFailRunner struct{}

func (startFailRunner) Run(context.Context, session.Job) (session.Handle, error) {
	return nil, errors.New("start failed")
}
func TestRunReportsStartFailures(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := Run(ctx, []Scheduled{{Job: jobs(1)[0], At: 0}}, startFailRunner{}, NewManualClock(time.Unix(0, 0)))
	if err == nil || !strings.Contains(err.Error(), "start failures: 1") {
		t.Fatalf("err=%v", err)
	}
}

type runtimeFailRunner struct{}

func (runtimeFailRunner) Run(context.Context, session.Job) (session.Handle, error) {
	return runtimeFailHandle{}, nil
}

type runtimeFailHandle struct{}

func (runtimeFailHandle) Close() error { return nil }
func (runtimeFailHandle) Wait(context.Context) session.Observation {
	return session.Observation{Reason: session.Failed, Err: errors.New("runtime failed")}
}
func TestRunReportsRuntimeFailures(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := Run(ctx, []Scheduled{{Job: jobs(1)[0], At: 0}}, runtimeFailRunner{}, NewManualClock(time.Unix(0, 0)))
	if err == nil || !strings.Contains(err.Error(), "runtime failures: 1") {
		t.Fatalf("err=%v", err)
	}
}

func TestRunWithRetriesUsesSameBindingAfterConnectTimeout(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	clock := NewManualClock(time.Unix(0, 0))
	runner := &retryRunner{failuresBeforeConnect: 2, started: make(chan struct{}, 1), clock: clock}
	done := make(chan error, 1)
	go func() {
		done <- RunWithRetries(ctx, []Scheduled{{Job: config.Job{ID: 1, Protocol: config.SSH, Mode: config.Direct, AssetID: "asset-1", AccountID: "account-1"}}}, runner, clock, ConnectRetryPolicy{MaxRetries: 3})
	}()
	for i := 0; i < 3; i++ {
		<-runner.started
	}
	cancel()
	if err := <-done; err != context.Canceled {
		t.Fatalf("err=%v", err)
	}
	runner.mu.Lock()
	defer runner.mu.Unlock()
	if len(runner.jobs) != 3 {
		t.Fatalf("attempts=%d", len(runner.jobs))
	}
	for _, job := range runner.jobs {
		if job.AssetID != "asset-1" || job.AccountID != "account-1" {
			t.Fatalf("retry binding changed: %+v", job)
		}
	}
}

func TestRunWithRetriesRetriesGraphicalPreConnectTimeout(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	clock := NewManualClock(time.Unix(0, 0))
	runner := &graphicalRetryRunner{failuresBeforeConnect: 2, started: make(chan struct{}, 3)}
	done := make(chan error, 1)
	go func() {
		done <- RunWithRetries(ctx, []Scheduled{{Job: config.Job{ID: 1, Protocol: config.RDP, Mode: config.Browser, AssetID: "rdp-asset-1", AccountID: "rdp-account-1"}}}, runner, clock, ConnectRetryPolicy{MaxRetries: 3})
	}()
	for i := 0; i < 3; i++ {
		select {
		case <-runner.started:
		case <-time.After(100 * time.Millisecond):
			cancel()
			<-done
			t.Fatalf("attempt %d was not started", i+1)
		}
	}
	cancel()
	if err := <-done; err != context.Canceled {
		t.Fatalf("err=%v", err)
	}
	runner.mu.Lock()
	defer runner.mu.Unlock()
	if len(runner.jobs) != 3 {
		t.Fatalf("attempts=%d", len(runner.jobs))
	}
	for _, job := range runner.jobs {
		if job.Protocol != config.RDP || job.Mode != config.Browser || job.AssetID != "rdp-asset-1" || job.AccountID != "rdp-account-1" {
			t.Fatalf("retry job=%+v", job)
		}
	}
}

func TestRunWithRetriesStopsAfterThreeAdditionalConnectAttempts(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	clock := NewManualClock(time.Unix(0, 0))
	runner := &retryRunner{failuresBeforeConnect: 4, started: make(chan struct{}, 4), clock: clock}
	done := make(chan error, 1)
	go func() {
		done <- RunWithRetries(ctx, []Scheduled{{Job: config.Job{ID: 1, Protocol: config.SSH, Mode: config.Direct, AssetID: "asset-1", AccountID: "account-1"}}}, runner, clock, ConnectRetryPolicy{MaxRetries: 3})
	}()
	for i := 0; i < 4; i++ {
		<-runner.started
	}
	cancel()
	err := <-done
	if err == nil || !strings.Contains(err.Error(), "start failures: 1") {
		t.Fatalf("err=%v", err)
	}
	runner.mu.Lock()
	defer runner.mu.Unlock()
	if len(runner.jobs) != 4 {
		t.Fatalf("attempts=%d", len(runner.jobs))
	}
}

func TestRunWithRetriesRetriesSSHGenericTimeout(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	clock := NewManualClock(time.Unix(0, 0))
	runner := &genericTimeoutRunner{failuresBeforeConnect: 2, started: make(chan struct{}, 3), clock: clock}
	done := make(chan error, 1)
	go func() {
		done <- RunWithRetries(ctx, []Scheduled{{Job: config.Job{ID: 1, Protocol: config.SSH, Mode: config.Direct, AssetID: "asset-1", AccountID: "account-1"}}}, runner, clock, ConnectRetryPolicy{MaxRetries: 3})
	}()
	for i := 0; i < 3; i++ {
		<-runner.started
	}
	cancel()
	if err := <-done; err != context.Canceled {
		t.Fatalf("err=%v", err)
	}
	runner.mu.Lock()
	defer runner.mu.Unlock()
	if len(runner.jobs) != 3 {
		t.Fatalf("attempts=%d, want 3", len(runner.jobs))
	}
}

type retryRunner struct {
	mu                    sync.Mutex
	failuresBeforeConnect int
	jobs                  []session.Job
	started               chan struct{}
	clock                 *ManualClock
}

type genericTimeoutRunner struct {
	mu                    sync.Mutex
	failuresBeforeConnect int
	jobs                  []session.Job
	started               chan struct{}
	clock                 *ManualClock
}

func (r *genericTimeoutRunner) Run(_ context.Context, job session.Job) (session.Handle, error) {
	r.mu.Lock()
	r.jobs = append(r.jobs, job)
	attempt := len(r.jobs)
	r.mu.Unlock()
	r.started <- struct{}{}
	if attempt <= r.failuresBeforeConnect {
		return &connectAwareHandle{done: session.Observation{Reason: session.Failed, Err: errors.New("session connect: context deadline exceeded")}}, nil
	}
	h := &connectAwareHandle{connected: make(chan struct{}), done: session.Observation{Reason: session.Cancelled}}
	close(h.connected)
	return h, nil
}

func (r *retryRunner) Run(_ context.Context, job session.Job) (session.Handle, error) {
	r.mu.Lock()
	r.jobs = append(r.jobs, job)
	attempt := len(r.jobs)
	r.mu.Unlock()
	r.started <- struct{}{}
	if attempt <= r.failuresBeforeConnect {
		return &connectAwareHandle{done: session.Observation{Reason: session.Failed, Err: errors.New("PAM session connect timeout: context deadline exceeded")}}, nil
	}
	h := &connectAwareHandle{connected: make(chan struct{}), done: session.Observation{Reason: session.Cancelled}}
	close(h.connected)
	return h, nil
}

type connectAwareHandle struct {
	connected chan struct{}
	done      session.Observation
}

type graphicalRetryRunner struct {
	mu                    sync.Mutex
	failuresBeforeConnect int
	jobs                  []session.Job
	started               chan struct{}
}

func (r *graphicalRetryRunner) Run(_ context.Context, job session.Job) (session.Handle, error) {
	r.mu.Lock()
	r.jobs = append(r.jobs, job)
	attempt := len(r.jobs)
	r.mu.Unlock()
	r.started <- struct{}{}
	if attempt <= r.failuresBeforeConnect {
		return &connectAwareHandle{done: session.Observation{Reason: session.Failed, Err: errors.New("graphical session connect timeout: context deadline exceeded")}}, nil
	}
	h := &connectAwareHandle{connected: make(chan struct{}), done: session.Observation{Reason: session.Cancelled}}
	close(h.connected)
	return h, nil
}

func (h *connectAwareHandle) Connected() <-chan struct{} { return h.connected }
func (h *connectAwareHandle) Close() error               { return nil }
func (h *connectAwareHandle) Wait(context.Context) session.Observation {
	return h.done
}

func TestPlanFitsRampAndIsReproducible(t *testing.T) {
	a := Plan(jobs(1000), 10*time.Minute, 42, 0.10)
	b := Plan(jobs(1000), 10*time.Minute, 42, 0.10)
	if len(a) != 1000 || len(b) != 1000 {
		t.Fatal("wrong plan size")
	}
	for i := range a {
		if a[i].At != b[i].At {
			t.Fatalf("offset %d is not reproducible", i)
		}
		if a[i].At < 0 || a[i].At >= 10*time.Minute {
			t.Fatalf("offset outside ramp: %s", a[i].At)
		}
		if i > 0 && a[i].At < a[i-1].At {
			t.Fatal("plan is not ordered")
		}
	}
}

type fakeRunner struct {
	mu              sync.Mutex
	started, closed int
	startedCh       chan struct{}
	jobs            []session.Job
}

func (f *fakeRunner) Run(ctx context.Context, job session.Job) (session.Handle, error) {
	f.mu.Lock()
	f.started++
	f.jobs = append(f.jobs, job)
	f.mu.Unlock()
	select {
	case f.startedCh <- struct{}{}:
	default:
	}
	return fakeHandle{f: f}, nil
}

func TestRunPreservesBoundAssetIDs(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	runner := &fakeRunner{startedCh: make(chan struct{}, 1)}
	job := config.Job{ID: 1, Protocol: config.SSH, AssetID: "asset-bound", AccountID: "account-bound"}
	done := make(chan error, 1)
	go func() { done <- Run(ctx, []Scheduled{{Job: job}}, runner, NewManualClock(time.Unix(0, 0))) }()
	<-runner.startedCh
	cancel()
	<-done
	runner.mu.Lock()
	defer runner.mu.Unlock()
	if len(runner.jobs) != 1 || runner.jobs[0].AssetID != job.AssetID || runner.jobs[0].AccountID != job.AccountID {
		t.Fatalf("jobs=%+v", runner.jobs)
	}
}

type fakeHandle struct{ f *fakeRunner }

func (h fakeHandle) Wait(ctx context.Context) session.Observation {
	return session.Observation{Reason: session.Cancelled}
}
func (h fakeHandle) Close() error { h.f.mu.Lock(); h.f.closed++; h.f.mu.Unlock(); return nil }

func TestRunCancellationClosesStartedSessions(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	runner := &fakeRunner{startedCh: make(chan struct{}, 1)}
	clock := NewManualClock(time.Unix(0, 0))
	done := make(chan error, 1)
	plan := []Scheduled{{Job: jobs(1)[0], At: 0}, {Job: jobs(2)[1], At: time.Second}}
	go func() { done <- Run(ctx, plan, runner, clock) }()
	<-runner.startedCh
	cancel()
	clock.Advance(5 * time.Second)
	if err := <-done; err != context.Canceled {
		t.Fatalf("got %v", err)
	}
	runner.mu.Lock()
	defer runner.mu.Unlock()
	if runner.started == 0 || runner.closed != runner.started {
		t.Fatalf("started=%d closed=%d", runner.started, runner.closed)
	}
}
