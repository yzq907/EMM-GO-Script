package browser

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeClient struct {
	active, peak atomic.Int64
	release      <-chan struct{}
	mu           sync.Mutex
	jobs         []Job
}

func (f *fakeClient) Run(ctx context.Context, job Job) (Result, error) {
	n := f.active.Add(1)
	defer f.active.Add(-1)
	for {
		old := f.peak.Load()
		if n <= old || f.peak.CompareAndSwap(old, n) {
			break
		}
	}
	f.mu.Lock()
	f.jobs = append(f.jobs, job)
	f.mu.Unlock()
	select {
	case <-ctx.Done():
		return Result{}, ctx.Err()
	case <-f.release:
		return Result{JobID: job.ID}, nil
	}
}
func (f *fakeClient) Close() error { return nil }

func TestPoolBoundsConcurrencyAndAppliesBackpressure(t *testing.T) {
	release := make(chan struct{})
	client := &fakeClient{release: release}
	p := NewPool(2, func(int) (Client, error) { return client, nil })
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	results := make(chan error, 3)
	for i := 0; i < 3; i++ {
		go func(id int) { _, err := p.Run(ctx, Job{ID: id, Protocol: "rdp"}); results <- err }(i)
	}
	time.Sleep(40 * time.Millisecond)
	if got := client.peak.Load(); got != 2 {
		t.Fatalf("peak=%d want 2", got)
	}
	close(release)
	for i := 0; i < 3; i++ {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestPoolRejectsUnsupportedProtocol(t *testing.T) {
	p := NewPool(1, func(int) (Client, error) { return &fakeClient{release: make(chan struct{})}, nil })
	defer p.Close()
	if _, err := p.Run(context.Background(), Job{ID: 1, Protocol: "ssh"}); err == nil {
		t.Fatal("expected validation error")
	}
}

func TestPoolAcceptsMySQLAndRejectsSSH(t *testing.T) {
	release := make(chan struct{})
	close(release)
	p := NewPool(1, func(int) (Client, error) { return &fakeClient{release: release}, nil })
	defer p.Close()
	if _, err := p.Run(context.Background(), Job{ID: 1, Protocol: "mysql"}); err != nil {
		t.Fatalf("mysql browser job was rejected: %v", err)
	}
	if _, err := p.Run(context.Background(), Job{ID: 2, Protocol: "ssh"}); err == nil {
		t.Fatal("ssh must remain unsupported by the browser pool")
	}
}

type failingClient struct{}

func (failingClient) Run(context.Context, Job) (Result, error) {
	return Result{}, context.DeadlineExceeded
}
func (failingClient) Close() error { return nil }

type successClient struct{}

func (successClient) Run(_ context.Context, job Job) (Result, error) {
	return Result{JobID: job.ID}, nil
}
func (successClient) Close() error { return nil }

func TestPoolRestartsFailedWorkerAndRetriesOnce(t *testing.T) {
	var creates atomic.Int64
	p := NewPool(1, func(int) (Client, error) {
		if creates.Add(1) == 1 {
			return failingClient{}, nil
		}
		return successClient{}, nil
	})
	defer p.Close()
	result, err := p.Run(context.Background(), Job{ID: 9, Protocol: "web"})
	if err != nil || result.JobID != 9 || creates.Load() != 2 {
		t.Fatalf("result=%+v creates=%d err=%v", result, creates.Load(), err)
	}
}

func TestPoolAllowsMultipleSessionsPerWorker(t *testing.T) {
	release := make(chan struct{})
	client := &fakeClient{release: release}
	p := NewPoolWithCapacity(1, 3, func(int) (Client, error) { return client, nil })
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	results := make(chan error, 3)
	for i := 0; i < 3; i++ {
		go func(id int) { _, err := p.Run(ctx, Job{ID: id, Protocol: "vnc"}); results <- err }(i)
	}
	time.Sleep(40 * time.Millisecond)
	if client.peak.Load() != 3 {
		t.Fatalf("peak=%d want 3", client.peak.Load())
	}
	close(release)
	for i := 0; i < 3; i++ {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	_ = p.Close()
}
