package engine

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"pam-loadtest/internal/browser"
	"pam-loadtest/internal/config"
	"pam-loadtest/internal/pam"
	"pam-loadtest/internal/session"
	"pam-loadtest/internal/transport"
)

func TestCancellationOnlyRejectsJoinedCleanupFailure(t *testing.T) {
	if !cancellationOnly(context.Canceled, context.Canceled) {
		t.Fatal("plain context cancellation must remain a cancellation")
	}
	if cancellationOnly(errors.Join(context.Canceled, errors.New("close failed")), context.Canceled) {
		t.Fatal("joined cleanup failure must be classified as a runtime failure")
	}
}

type fakePAM struct {
	mu                           sync.Mutex
	calls                        []string
	reviewedAsset                string
	createdAsset, createdAccount string
	waitConnected                func(context.Context, string, time.Duration) (pam.Session, error)
	sessionStatus                func(context.Context, string) (pam.Session, error)
}

func (f *fakePAM) ReviewCandidates(_ context.Context, assetID string) ([]pam.Candidate, error) {
	f.calls = append(f.calls, "review")
	f.reviewedAsset = assetID
	return nil, nil
}
func (f *fakePAM) CreateSession(_ context.Context, assetID, accountID, mode string) (pam.Session, error) {
	f.calls = append(f.calls, "create:"+mode)
	f.createdAsset, f.createdAccount = assetID, accountID
	return pam.Session{ID: "s-1"}, nil
}

func TestRunnerUsesPerJobAssetBinding(t *testing.T) {
	p := &fakePAM{}
	direct := func(ctx context.Context, o transport.WebSocketOptions) (transport.Stats, error) {
		if err := o.AfterDial(); err != nil {
			return transport.Stats{}, err
		}
		<-ctx.Done()
		return transport.Stats{}, ctx.Err()
	}
	r := New(p, nil, fakeMetrics{}, map[config.Protocol]Target{config.SSH: {AssetID: "legacy-a", AccountID: "legacy-u"}}, direct)
	h, err := r.Run(context.Background(), session.Job{ID: 9, Protocol: config.SSH, AssetID: "bound-a", AccountID: "bound-u"})
	if err != nil {
		t.Fatal(err)
	}
	_ = h.Close()
	_ = h.Wait(context.Background())
	if p.reviewedAsset != "bound-a" || p.createdAsset != "bound-a" || p.createdAccount != "bound-u" {
		t.Fatalf("review=%q create=%q/%q", p.reviewedAsset, p.createdAsset, p.createdAccount)
	}
}

func TestRunnerFallsBackToLegacyProtocolTarget(t *testing.T) {
	p := &fakePAM{}
	direct := func(ctx context.Context, _ transport.WebSocketOptions) (transport.Stats, error) {
		<-ctx.Done()
		return transport.Stats{}, ctx.Err()
	}
	r := New(p, nil, fakeMetrics{}, map[config.Protocol]Target{config.SSH: {AssetID: "legacy-a", AccountID: "legacy-u"}}, direct)
	h, err := r.Run(context.Background(), session.Job{ID: 10, Protocol: config.SSH})
	if err != nil {
		t.Fatal(err)
	}
	_ = h.Close()
	_ = h.Wait(context.Background())
	if p.reviewedAsset != "legacy-a" || p.createdAsset != "legacy-a" || p.createdAccount != "legacy-u" {
		t.Fatalf("review=%q create=%q/%q", p.reviewedAsset, p.createdAsset, p.createdAccount)
	}
}
func (f *fakePAM) CreateDBSession(context.Context, string, string) (pam.Session, error) {
	f.calls = append(f.calls, "create:db")
	return pam.Session{ID: "db-1"}, nil
}
func (f *fakePAM) CreateWebSession(context.Context, string, string) (pam.Session, error) {
	f.calls = append(f.calls, "create:web")
	return pam.Session{ID: "web-1"}, nil
}
func (f *fakePAM) WebRTCOffer(context.Context, string, pam.WebRTCOffer) (pam.WebRTCAnswer, error) {
	return pam.WebRTCAnswer{}, nil
}
func (f *fakePAM) WebRTCCandidate(context.Context, string, pam.WebRTCCandidate) error {
	return nil
}
func (f *fakePAM) WebNavigate(context.Context, string, string) error { return nil }
func (f *fakePAM) WebResize(context.Context, string, int, int) error { return nil }
func (f *fakePAM) CloseWebSession(context.Context, string) error     { return nil }
func (f *fakePAM) Connect(context.Context, string) error {
	f.calls = append(f.calls, "connect")
	return nil
}
func (f *fakePAM) WaitConnected(ctx context.Context, sessionID string, interval time.Duration) (pam.Session, error) {
	f.calls = append(f.calls, "wait-connected")
	if f.waitConnected != nil {
		return f.waitConnected(ctx, sessionID, interval)
	}
	return pam.Session{ID: "s-1", Status: "connected"}, nil
}
func (f *fakePAM) SessionStatus(ctx context.Context, sessionID string) (pam.Session, error) {
	f.mu.Lock()
	f.calls = append(f.calls, "session-status")
	f.mu.Unlock()
	if f.sessionStatus != nil {
		return f.sessionStatus(ctx, sessionID)
	}
	return pam.Session{ID: sessionID, Status: "connected"}, nil
}
func (f *fakePAM) Token() string                 { return "runtime-token" }
func (f *fakePAM) BaseURL() string               { return "http://pam.test" }
func (f *fakePAM) WebSocketHeaders() http.Header { return http.Header{"Cookie": {"sid=runtime"}} }
func (f *fakePAM) BrowserCookies() []http.Cookie {
	return []http.Cookie{{Name: "sid", Value: "runtime-cookie"}}
}

type fakeBrowser struct{ job browser.Job }

func (f *fakeBrowser) Run(ctx context.Context, j browser.Job) (browser.Result, error) {
	f.job = j
	<-ctx.Done()
	return browser.Result{JobID: j.ID}, ctx.Err()
}

type timeoutFakeBrowser struct{}

func (timeoutFakeBrowser) Run(context.Context, browser.Job) (browser.Result, error) {
	return browser.Result{}, errors.New("page.waitForFunction: Timeout 30000ms exceeded")
}

type fakeMetrics struct{}

func (fakeMetrics) Started(string, string)                  {}
func (fakeMetrics) Active(string, string, float64)          {}
func (fakeMetrics) Connected(string, string, time.Duration) {}
func (fakeMetrics) Failed(string, string, string)           {}
func (fakeMetrics) Disconnected(string, string, string)     {}
func (fakeMetrics) Traffic(string, string, int64, int64)    {}

type connectionMetrics struct{ connected chan time.Duration }

func (connectionMetrics) Started(string, string)         {}
func (connectionMetrics) Active(string, string, float64) {}
func (m connectionMetrics) Connected(_ string, _ string, latency time.Duration) {
	m.connected <- latency
}
func (connectionMetrics) Failed(string, string, string)        {}
func (connectionMetrics) Disconnected(string, string, string)  {}
func (connectionMetrics) Traffic(string, string, int64, int64) {}

func TestSSHRunnerOpensSocketThenConnects(t *testing.T) {
	p := &fakePAM{}
	dialed := make(chan struct{})
	direct := func(ctx context.Context, o transport.WebSocketOptions) (transport.Stats, error) {
		close(dialed)
		if err := o.AfterDial(); err != nil {
			return transport.Stats{}, err
		}
		<-ctx.Done()
		return transport.Stats{SentBytes: 10, ReceivedBytes: 20}, ctx.Err()
	}
	r := New(p, nil, fakeMetrics{}, map[config.Protocol]Target{config.SSH: {AssetID: "a", AccountID: "u", Interval: time.Second, Activity: "echo active"}}, direct)
	h, err := r.Run(context.Background(), session.Job{ID: 1, Protocol: config.SSH})
	if err != nil {
		t.Fatal(err)
	}
	<-dialed
	_ = h.Close()
	obs := h.Wait(context.Background())
	if obs.SentBytes != 10 || obs.ReceivedBytes != 20 {
		t.Fatalf("obs=%+v", obs)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	want := []string{"review", "create:native", "connect", "wait-connected"}
	if len(p.calls) != len(want) {
		t.Fatalf("calls=%v", p.calls)
	}
	for i := range want {
		if p.calls[i] != want[i] {
			t.Fatalf("calls=%v", p.calls)
		}
	}
}

func TestSSHRunnerBoundsAndClassifiesConnectWait(t *testing.T) {
	deadlineObserved := make(chan time.Duration, 1)
	p := &fakePAM{waitConnected: func(ctx context.Context, _ string, _ time.Duration) (pam.Session, error) {
		deadline, ok := ctx.Deadline()
		if !ok {
			deadlineObserved <- 0
			return pam.Session{Status: "connecting"}, context.DeadlineExceeded
		}
		deadlineObserved <- time.Until(deadline)
		return pam.Session{Status: "connecting"}, context.DeadlineExceeded
	}}
	direct := func(_ context.Context, options transport.WebSocketOptions) (transport.Stats, error) {
		return transport.Stats{}, options.AfterDial()
	}
	r := New(p, nil, fakeMetrics{}, map[config.Protocol]Target{config.SSH: {AssetID: "a", AccountID: "u"}}, direct)
	handle, err := r.Run(context.Background(), session.Job{ID: 1, Protocol: config.SSH})
	if err != nil {
		t.Fatal(err)
	}
	observation := handle.Wait(context.Background())
	if observation.Err == nil || !strings.Contains(observation.Err.Error(), "PAM session connect timeout") {
		t.Fatalf("observation=%+v", observation)
	}
	remaining := <-deadlineObserved
	if remaining < 59*time.Second || remaining > 61*time.Second {
		t.Fatalf("connect wait deadline=%s", remaining)
	}
}

func TestBrowserRunnerLetsFrontendCreateSessionAndExpandsURL(t *testing.T) {
	p := &fakePAM{}
	b := &fakeBrowser{}
	r := New(p, b, fakeMetrics{}, map[config.Protocol]Target{config.RDP: {AssetID: "a", AccountID: "u", BrowserURL: "http://pam.test/#/access?assetId={assetId}&protocol={protocol}&accountId={accountId}", Username: "runtime-user", Password: "runtime-pass"}}, nil)
	h, err := r.Run(context.Background(), session.Job{ID: 2, Protocol: config.RDP})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	_ = h.Close()
	_ = h.Wait(context.Background())
	if b.job.URL != "http://pam.test/#/access?assetId=a&protocol=rdp&accountId=u" || b.job.Protocol != "rdp" || b.job.Username != "" || b.job.Password != "" {
		t.Fatalf("job=%+v", b.job)
	}
	if len(b.job.Cookies) != 1 || b.job.Cookies[0].Name != "sid" || b.job.Cookies[0].Value != "runtime-cookie" || b.job.Cookies[0].URL != "http://pam.test" {
		t.Fatalf("browser cookies=%+v", b.job.Cookies)
	}
	if len(p.calls) != 1 || p.calls[0] != "review" {
		t.Fatalf("browser frontend must create the session; calls=%v", p.calls)
	}
}

func TestBrowserRunnerClassifiesUnconnectedTimeoutForRetry(t *testing.T) {
	r := New(&fakePAM{}, timeoutFakeBrowser{}, fakeMetrics{}, map[config.Protocol]Target{config.RDP: {AssetID: "a", AccountID: "u", BrowserURL: "http://pam.test/#/access"}}, nil)
	h, err := r.Run(context.Background(), session.Job{ID: 24, Protocol: config.RDP, Mode: config.Browser})
	if err != nil {
		t.Fatal(err)
	}
	observation := h.Wait(context.Background())
	if observation.Reason != session.Failed || observation.Err == nil || !strings.Contains(observation.Err.Error(), "graphical session connect timeout") {
		t.Fatalf("observation=%+v", observation)
	}
	select {
	case <-h.(session.ConnectionAware).Connected():
		t.Fatal("unconnected timeout signalled connected")
	default:
	}
}

func TestMySQLBrowserLetsFrontendCreateSessionAndPreservesBinding(t *testing.T) {
	p := &fakePAM{}
	b := &fakeBrowser{}
	r := New(p, b, fakeMetrics{}, map[config.Protocol]Target{config.MySQL: {
		AssetID:    "legacy-a",
		AccountID:  "legacy-u",
		BrowserURL: "http://pam.test/#/asset",
		Username:   "runtime-user",
		Password:   "runtime-pass",
	}}, nil)
	h, err := r.Run(context.Background(), session.Job{ID: 22, Protocol: config.MySQL, Mode: config.Browser, AssetID: "bound-a", AccountID: "bound-u"})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	_ = h.Close()
	_ = h.Wait(context.Background())
	if b.job.Protocol != "mysql" || b.job.URL != "http://pam.test/#/asset" || b.job.AssetID != "bound-a" || b.job.AccountID != "bound-u" {
		t.Fatalf("browser binding was not preserved: protocol=%q url=%q asset=%q account=%q", b.job.Protocol, b.job.URL, b.job.AssetID, b.job.AccountID)
	}
	if b.job.Username != "runtime-user" || b.job.Password != "runtime-pass" || len(b.job.Cookies) != 0 {
		t.Fatalf("mysql GUI must use visible login instead of cookie-only authentication: username=%q password_set=%t cookies=%d", b.job.Username, b.job.Password != "", len(b.job.Cookies))
	}
	if len(p.calls) != 1 || p.calls[0] != "review" {
		t.Fatalf("browser frontend must create the GUI session; calls=%v", p.calls)
	}
}

func TestMySQLDirectStillCreatesDBSession(t *testing.T) {
	p := &fakePAM{}
	dialed := make(chan struct{}, 1)
	direct := func(ctx context.Context, options transport.WebSocketOptions) (transport.Stats, error) {
		dialed <- struct{}{}
		if err := options.AfterDial(); err != nil {
			return transport.Stats{}, err
		}
		<-ctx.Done()
		return transport.Stats{}, ctx.Err()
	}
	r := New(p, nil, fakeMetrics{}, map[config.Protocol]Target{config.MySQL: {AssetID: "a", AccountID: "u"}}, direct)
	h, err := r.Run(context.Background(), session.Job{ID: 23, Protocol: config.MySQL, Mode: config.Direct})
	if err != nil {
		t.Fatal(err)
	}
	<-dialed
	_ = h.Close()
	_ = h.Wait(context.Background())
	if len(p.calls) != 2 || p.calls[0] != "review" || p.calls[1] != "create:db" {
		t.Fatalf("mysql direct calls=%v", p.calls)
	}
}

func TestDirectRDPRunsGuacamoleWithoutBrowser(t *testing.T) {
	p := &fakePAM{}
	b := &fakeBrowser{}
	called := make(chan GuacamoleOptions, 1)
	adapters := DirectAdapters{
		Guacamole: func(ctx context.Context, options GuacamoleOptions) (transport.Stats, error) {
			called <- options
			if err := options.AfterDial(); err != nil {
				return transport.Stats{}, err
			}
			<-ctx.Done()
			return transport.Stats{ReceivedBytes: 10}, ctx.Err()
		},
	}
	r := NewWithAdapters(p, b, fakeMetrics{}, map[config.Protocol]Target{config.RDP: {AssetID: "a", AccountID: "u", Interval: time.Second}}, adapters)
	h, err := r.Run(context.Background(), session.Job{ID: 3, Protocol: config.RDP, Mode: config.Direct})
	if err != nil {
		t.Fatal(err)
	}
	options := <-called
	_ = h.Close()
	_ = h.Wait(context.Background())
	if !strings.Contains(options.URL, "/sessions/s-1/tunnel") || b.job.ID != 0 {
		t.Fatalf("options=%+v browser=%+v", options, b.job)
	}
	if len(p.calls) < 3 || p.calls[1] != "create:guacd" || p.calls[2] != "connect" {
		t.Fatalf("calls=%v", p.calls)
	}
}

func TestDirectWebRunsWebRTCAdapterWithoutBrowser(t *testing.T) {
	p := &fakePAM{}
	b := &fakeBrowser{}
	called := make(chan WebOptions, 1)
	adapters := DirectAdapters{
		Web: func(ctx context.Context, _ WebPAM, options WebOptions) (transport.Stats, error) {
			called <- options
			<-ctx.Done()
			return transport.Stats{ReceivedBytes: 20}, ctx.Err()
		},
	}
	r := NewWithAdapters(p, b, fakeMetrics{}, map[config.Protocol]Target{config.Web: {AssetID: "a", AccountID: "u", Interval: time.Second}}, adapters)
	h, err := r.Run(context.Background(), session.Job{ID: 4, Protocol: config.Web, Mode: config.Direct})
	if err != nil {
		t.Fatal(err)
	}
	options := <-called
	_ = h.Close()
	_ = h.Wait(context.Background())
	if options.AssetID != "a" || options.AccountID != "u" || b.job.ID != 0 {
		t.Fatalf("options=%+v browser=%+v", options, b.job)
	}
}

func TestDirectObservationRecordsModeLatencyActivityAndWaitsForHandshake(t *testing.T) {
	p := &fakePAM{}
	lastActivity := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	releaseHandshake := make(chan struct{})
	metrics := connectionMetrics{connected: make(chan time.Duration, 1)}
	direct := func(ctx context.Context, options transport.WebSocketOptions) (transport.Stats, error) {
		<-releaseHandshake
		if err := options.AfterDial(); err != nil {
			return transport.Stats{}, err
		}
		<-ctx.Done()
		return transport.Stats{SentMessages: 7, SentBytes: 70, ReceivedBytes: 90, LastActivity: lastActivity}, ctx.Err()
	}
	runner := New(p, nil, metrics, map[config.Protocol]Target{config.SSH: {AssetID: "asset", AccountID: "account", Activity: "echo active"}}, direct)
	handle, err := runner.Run(context.Background(), session.Job{ID: 11, Protocol: config.SSH, Mode: config.Direct})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-metrics.connected:
		t.Fatal("connected metric was emitted before the direct handshake")
	default:
	}
	close(releaseHandshake)
	select {
	case latency := <-metrics.connected:
		if latency <= 0 {
			t.Fatalf("latency=%s", latency)
		}
	case <-time.After(time.Second):
		t.Fatal("connected metric was not emitted after handshake")
	}
	_ = handle.Close()
	observation := handle.Wait(context.Background())
	if observation.Mode != config.Direct || observation.ConnectLatency <= 0 || observation.ActivityEvents != 7 || !observation.LastActivity.Equal(lastActivity) {
		t.Fatalf("observation=%+v", observation)
	}
}

func TestSSHRunnerReconnectsSamePAMSessionWithoutRepeatingStartupCommand(t *testing.T) {
	p := &fakePAM{}
	reconnected := make(chan transport.WebSocketOptions, 1)
	var attempts int
	direct := func(ctx context.Context, options transport.WebSocketOptions) (transport.Stats, error) {
		attempts++
		if attempts == 1 {
			if err := options.AfterDial(); err != nil {
				return transport.Stats{}, err
			}
			return transport.Stats{SentMessages: 2, SentBytes: 20, ReceivedBytes: 30, LastActivity: time.Date(2026, 8, 6, 15, 0, 0, 0, time.UTC)}, errors.New("websocket read failed: close 1006")
		}
		if options.AfterDial != nil {
			return transport.Stats{}, errors.New("reconnect must not reconnect the PAM session")
		}
		if len(options.StartupPayloads) != 0 {
			return transport.Stats{}, errors.New("reconnect must not repeat the SSH startup command")
		}
		reconnected <- options
		<-ctx.Done()
		return transport.Stats{SentMessages: 3, SentBytes: 40, ReceivedBytes: 50, LastActivity: time.Date(2026, 8, 6, 15, 1, 0, 0, time.UTC)}, ctx.Err()
	}
	runner := New(p, nil, fakeMetrics{}, map[config.Protocol]Target{config.SSH: {AssetID: "asset", AccountID: "account", Interval: time.Second, Activity: "echo active"}}, direct)
	h, err := runner.Run(context.Background(), session.Job{ID: 14, Protocol: config.SSH, Mode: config.Direct})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case options := <-reconnected:
		if !strings.Contains(options.URL, "/sessions/s-1/ssh") {
			t.Fatalf("reconnect URL=%q", options.URL)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("SSH transport was not reconnected")
	}
	_ = h.Close()
	observation := h.Wait(context.Background())
	if observation.Reason != session.Cancelled || observation.ActivityEvents != 5 || observation.SentBytes != 60 || observation.ReceivedBytes != 80 || !observation.LastActivity.Equal(time.Date(2026, 8, 6, 15, 1, 0, 0, time.UTC)) {
		t.Fatalf("observation=%+v", observation)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	want := []string{"review", "create:native", "connect", "wait-connected", "session-status"}
	if len(p.calls) != len(want) {
		t.Fatalf("calls=%v want=%v", p.calls, want)
	}
	for i := range want {
		if p.calls[i] != want[i] {
			t.Fatalf("calls=%v want=%v", p.calls, want)
		}
	}
}

func TestSSHRunnerWaitsForPAMSessionToReconnectBeforeRestoringTransport(t *testing.T) {
	statuses := []string{"connecting", "connected"}
	p := &fakePAM{sessionStatus: func(context.Context, string) (pam.Session, error) {
		status := statuses[0]
		statuses = statuses[1:]
		return pam.Session{ID: "s-1", Status: status}, nil
	}}
	reconnected := make(chan struct{}, 1)
	attempts := 0
	direct := func(ctx context.Context, options transport.WebSocketOptions) (transport.Stats, error) {
		attempts++
		if attempts == 1 {
			if err := options.AfterDial(); err != nil {
				return transport.Stats{}, err
			}
			return transport.Stats{SentMessages: 1, ReceivedBytes: 1, LastActivity: time.Now()}, errors.New("websocket read failed: close 1006")
		}
		if len(options.StartupPayloads) != 0 {
			return transport.Stats{}, errors.New("reconnect repeated startup command")
		}
		reconnected <- struct{}{}
		<-ctx.Done()
		return transport.Stats{SentMessages: 1, ReceivedBytes: 1, LastActivity: time.Now()}, ctx.Err()
	}
	runner := New(p, nil, fakeMetrics{}, map[config.Protocol]Target{config.SSH: {AssetID: "asset", AccountID: "account", Interval: time.Second, Activity: "echo active"}}, direct)
	h, err := runner.Run(context.Background(), session.Job{ID: 15, Protocol: config.SSH, Mode: config.Direct})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-reconnected:
	case <-time.After(6 * time.Second):
		t.Fatal("SSH transport was not restored after PAM returned to connected")
	}
	_ = h.Close()
	if observation := h.Wait(context.Background()); observation.Reason != session.Cancelled || observation.ActivityEvents != 2 {
		t.Fatalf("observation=%+v", observation)
	}
}

type activeFakeBrowser struct{}

func (activeFakeBrowser) Run(ctx context.Context, job browser.Job) (browser.Result, error) {
	if job.OnConnected != nil {
		job.OnConnected(25 * time.Millisecond)
	}
	<-ctx.Done()
	return browser.Result{JobID: job.ID, Heartbeats: 5, LastActivity: time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)}, ctx.Err()
}

func TestBrowserObservationUsesHeartbeatsAsActivity(t *testing.T) {
	runner := New(&fakePAM{}, activeFakeBrowser{}, fakeMetrics{}, map[config.Protocol]Target{config.RDP: {AssetID: "asset", AccountID: "account", BrowserURL: "http://pam.test/access"}}, nil)
	handle, err := runner.Run(context.Background(), session.Job{ID: 12, Protocol: config.RDP, Mode: config.Browser})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	_ = handle.Close()
	observation := handle.Wait(context.Background())
	if observation.Mode != config.Browser || observation.ConnectLatency != 25*time.Millisecond || observation.ActivityEvents != 5 || !observation.LastActivity.Equal(time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)) {
		t.Fatalf("observation=%+v", observation)
	}
}

type timingFakeBrowser struct{}

func (timingFakeBrowser) Run(ctx context.Context, job browser.Job) (browser.Result, error) {
	if job.OnConnected != nil {
		job.OnConnected(2200 * time.Millisecond)
	}
	<-ctx.Done()
	return browser.Result{JobID: job.ID, Heartbeats: 1, LastActivity: time.Now(), PrepareLatency: 7100 * time.Millisecond, EditorReadyLatency: 400 * time.Millisecond}, ctx.Err()
}

func TestMySQLGUIBrowserObservationIncludesPhaseTimings(t *testing.T) {
	runner := New(&fakePAM{}, timingFakeBrowser{}, fakeMetrics{}, map[config.Protocol]Target{config.MySQL: {AssetID: "asset", AccountID: "account", BrowserURL: "http://pam.test/#/asset"}}, nil)
	handle, err := runner.Run(context.Background(), session.Job{ID: 13, Protocol: config.MySQL, Mode: config.Browser})
	if err != nil {
		t.Fatal(err)
	}
	if err := handle.Close(); err != nil {
		t.Fatal(err)
	}
	observation := handle.Wait(context.Background())
	if observation.ConnectLatency != 2200*time.Millisecond || observation.PrepareLatency != 7100*time.Millisecond || observation.EditorReadyLatency != 400*time.Millisecond {
		t.Fatalf("observation=%+v", observation)
	}
}
