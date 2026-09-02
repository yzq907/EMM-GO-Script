package scheduler

import (
	"context"
	"fmt"
	"math/rand"
	"sort"
	"strings"
	"sync"
	"time"

	"pam-loadtest/internal/config"
	"pam-loadtest/internal/session"
)

type Scheduled struct {
	Job config.Job
	At  time.Duration
}

func Plan(jobs []config.Job, ramp time.Duration, seed int64, jitterFraction float64) []Scheduled {
	r := rand.New(rand.NewSource(seed))
	out := make([]Scheduled, len(jobs))
	step := float64(ramp) / float64(len(jobs))
	for i, job := range jobs {
		base := (float64(i) + .5) * step
		jitter := (r.Float64()*2 - 1) * step * jitterFraction
		at := time.Duration(base + jitter)
		if at < 0 {
			at = 0
		}
		if at >= ramp {
			at = ramp - 1
		}
		out[i] = Scheduled{Job: job, At: at}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].At < out[j].At })
	return out
}

type Clock interface {
	Now() time.Time
	After(time.Duration) <-chan time.Time
}
type realClock struct{}

func (realClock) Now() time.Time                         { return time.Now() }
func (realClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

func Run(ctx context.Context, plan []Scheduled, runner session.Runner, clock Clock) error {
	return RunWithRetries(ctx, plan, runner, clock, ConnectRetryPolicy{})
}

type ConnectRetryPolicy struct {
	MaxRetries int
	Backoffs   []time.Duration
}

type activeHandle struct {
	handle    session.Handle
	connected bool
	done      <-chan session.Observation
}

func RunWithRetries(ctx context.Context, plan []Scheduled, runner session.Runner, clock Clock, policy ConnectRetryPolicy) error {
	start := clock.Now()
	if policy.MaxRetries < 0 {
		policy.MaxRetries = 0
	}
	var handles []activeHandle
	var handlesMu sync.Mutex
	var workers sync.WaitGroup
	startFailures := 0
	var firstStartError, firstRuntimeError error
	var failuresMu sync.Mutex
	recordStartFailure := func(err error) {
		failuresMu.Lock()
		defer failuresMu.Unlock()
		startFailures++
		if firstStartError == nil {
			firstStartError = err
		}
	}
	recordRuntimeFailure := func(err error) {
		failuresMu.Lock()
		defer failuresMu.Unlock()
		if firstRuntimeError == nil {
			firstRuntimeError = err
		}
	}
	launch := func(item Scheduled) {
		workers.Add(1)
		go func() {
			defer workers.Done()
			job := session.Job{ID: item.Job.ID, Protocol: item.Job.Protocol, Mode: item.Job.Mode, AssetID: item.Job.AssetID, AccountID: item.Job.AccountID}
			for retry := 0; ; retry++ {
				h, err := runner.Run(ctx, job)
				if err != nil {
					recordStartFailure(err)
					return
				}
				connected := false
				var done <-chan session.Observation
				if aware, ok := h.(session.ConnectionAware); ok {
					result := make(chan session.Observation, 1)
					done = result
					go func() { result <- observe(h, context.Background()) }()
					select {
					case <-aware.Connected():
						connected = true
					case observation := <-done:
						if retry < policy.MaxRetries && retryableConnectTimeout(job, observation) {
							reportRetry(h)
							if !waitRetry(ctx, clock, retryBackoff(policy, retry+1)) {
								finalize(h, observation, false)
								recordStartFailure(ctx.Err())
								return
							}
							continue
						}
						if retry > 0 {
							reportRetryExhausted(h)
						}
						finalize(h, observation, false)
						recordStartFailure(observation.Err)
						return
					case <-ctx.Done():
						_ = h.Close()
						observation := <-done
						finalize(h, observation, false)
						recordStartFailure(ctx.Err())
						return
					}
				}
				if retry > 0 && connected {
					reportRetrySucceeded(h)
				}
				handlesMu.Lock()
				handles = append(handles, activeHandle{handle: h, connected: connected, done: done})
				handlesMu.Unlock()
				return
			}
		}()
	}
	var cause error
	scheduling := true
	for _, item := range plan {
		if !scheduling {
			break
		}
		wait := item.At - clock.Now().Sub(start)
		if wait > 0 {
			select {
			case <-ctx.Done():
				cause = ctx.Err()
				scheduling = false
				continue
			case <-clock.After(wait):
			}
		}
		launch(item)
	}
	if cause == nil {
		<-ctx.Done()
		cause = ctx.Err()
	}
	workers.Wait()
	handlesMu.Lock()
	active := append([]activeHandle(nil), handles...)
	handlesMu.Unlock()
	for _, h := range active {
		_ = h.handle.Close()
	}
	runtimeFailures := 0
	for _, h := range active {
		waitCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		var observation session.Observation
		if h.done != nil {
			select {
			case observation = <-h.done:
			case <-waitCtx.Done():
				observation = session.Observation{Reason: session.Cancelled, Err: waitCtx.Err()}
			}
		} else {
			observation = observe(h.handle, waitCtx)
		}
		cancel()
		// The scenario context has already been cancelled by this point
		// (teardown). A transport error that races the cancellation is
		// teardown noise, not a runtime failure: the run goroutine may observe
		// the PAM-side WebSocket close a few milliseconds before the
		// cancellation is visible to ctx.Err(), so reclassify transport
		// failures surfaced after teardown began as Cancelled.
		if observation.Reason == session.Failed && ctx.Err() != nil && isTransportFailure(observation.Err) {
			observation.Reason = session.Cancelled
			observation.Err = ctx.Err()
		}
		finalize(h.handle, observation, h.connected)
		if observation.Reason == session.Failed {
			runtimeFailures++
			recordRuntimeFailure(observation.Err)
		}
	}
	failuresMu.Lock()
	defer failuresMu.Unlock()
	if startFailures > 0 || runtimeFailures > 0 {
		return fmt.Errorf("load run failed (start failures: %d, runtime failures: %d, first start error: %v, first runtime error: %v)", startFailures, runtimeFailures, firstStartError, firstRuntimeError)
	}
	return cause
}

func observe(h session.Handle, ctx context.Context) session.Observation {
	if source, ok := h.(session.ObservationSource); ok {
		return source.Observe(ctx)
	}
	return h.Wait(ctx)
}
func finalize(h session.Handle, observation session.Observation, connected bool) {
	if finalizer, ok := h.(session.OutcomeFinalizer); ok {
		finalizer.Finalize(observation, connected)
	}
}
func reportRetry(h session.Handle) {
	if reporter, ok := h.(session.ConnectRetryReporter); ok {
		reporter.ConnectRetry()
	}
}
func reportRetrySucceeded(h session.Handle) {
	if reporter, ok := h.(session.ConnectRetryReporter); ok {
		reporter.ConnectRetrySucceeded()
	}
}
func reportRetryExhausted(h session.Handle) {
	if reporter, ok := h.(session.ConnectRetryReporter); ok {
		reporter.ConnectRetryExhausted()
	}
}
func waitRetry(ctx context.Context, clock Clock, delay time.Duration) bool {
	if delay <= 0 {
		return ctx.Err() == nil
	}
	select {
	case <-ctx.Done():
		return false
	case <-clock.After(delay):
		return true
	}
}
func retryBackoff(policy ConnectRetryPolicy, retry int) time.Duration {
	if retry > 0 && retry <= len(policy.Backoffs) {
		return policy.Backoffs[retry-1]
	}
	return 0
}
func retryableConnectTimeout(job session.Job, observation session.Observation) bool {
	if observation.Reason != session.Failed || observation.Err == nil {
		return false
	}
	message := strings.ToLower(observation.Err.Error())
	if job.Protocol == config.SSH && job.Mode == config.Direct {
		// Retry SSH connect failures caused by PAM session-establishment
		// timeouts as well as generic connect timeouts, so a transient PAM
		// bottleneck does not permanently lose a session.
		return strings.Contains(message, "pam session connect timeout") ||
			strings.Contains(message, "timeout") ||
			strings.Contains(message, "timed out") ||
			strings.Contains(message, "deadline exceeded")
	}
	switch job.Protocol {
	case config.RDP, config.VNC, config.Web, config.MySQL:
		return strings.Contains(message, "graphical session connect timeout")
	default:
		return false
	}
}

// isTransportFailure reports whether err matches the "transport_closed"
// failure category. Transport errors racing scenario teardown are
// reclassified as cancelled by the teardown loop.
func isTransportFailure(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "websocket") ||
		strings.Contains(message, "unexpected eof") ||
		strings.Contains(message, "connection reset") ||
		strings.Contains(message, "broken pipe")
}

type waiter struct {
	at time.Time
	ch chan time.Time
}
type ManualClock struct {
	mu      sync.Mutex
	now     time.Time
	waiters []waiter
}

func NewManualClock(now time.Time) *ManualClock { return &ManualClock{now: now} }
func (c *ManualClock) Now() time.Time           { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *ManualClock) After(d time.Duration) <-chan time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	ch := make(chan time.Time, 1)
	if d <= 0 {
		ch <- c.now
		return ch
	}
	c.waiters = append(c.waiters, waiter{at: c.now.Add(d), ch: ch})
	return ch
}
func (c *ManualClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
	remaining := c.waiters[:0]
	for _, w := range c.waiters {
		if !w.at.After(c.now) {
			w.ch <- c.now
		} else {
			remaining = append(remaining, w)
		}
	}
	c.waiters = remaining
}
