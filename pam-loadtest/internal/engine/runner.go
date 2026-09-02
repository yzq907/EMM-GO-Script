package engine

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"pam-loadtest/internal/browser"
	"pam-loadtest/internal/config"
	"pam-loadtest/internal/pam"
	"pam-loadtest/internal/protocol"
	"pam-loadtest/internal/session"
	"pam-loadtest/internal/transport"
)

const (
	pamSessionConnectTimeout      = 60 * time.Second
	sshTransportReconnectAttempts = 3
	sshTransportStateTimeout      = 30 * time.Second
)

var sshTransportReconnectBackoff = []time.Duration{2 * time.Second, 5 * time.Second, 10 * time.Second}

type PAM interface {
	ReviewCandidates(context.Context, string) ([]pam.Candidate, error)
	CreateSession(context.Context, string, string, string) (pam.Session, error)
	CreateDBSession(context.Context, string, string) (pam.Session, error)
	CreateWebSession(context.Context, string, string) (pam.Session, error)
	Connect(context.Context, string) error
	SessionStatus(context.Context, string) (pam.Session, error)
	WaitConnected(context.Context, string, time.Duration) (pam.Session, error)
	Token() string
	BaseURL() string
	WebSocketHeaders() http.Header
	WebRTCOffer(context.Context, string, pam.WebRTCOffer) (pam.WebRTCAnswer, error)
	WebRTCCandidate(context.Context, string, pam.WebRTCCandidate) error
	WebNavigate(context.Context, string, string) error
	WebResize(context.Context, string, int, int) error
	CloseWebSession(context.Context, string) error
}
type Browser interface {
	Run(context.Context, browser.Job) (browser.Result, error)
}
type Metrics interface {
	Started(string, string)
	Active(string, string, float64)
	Connected(string, string, time.Duration)
	Failed(string, string, string)
	Disconnected(string, string, string)
	Traffic(string, string, int64, int64)
}
type DirectFunc func(context.Context, transport.WebSocketOptions) (transport.Stats, error)
type GuacamoleOptions = protocol.GuacamoleOptions
type WebOptions = protocol.WebOptions
type WebPAM = protocol.WebPAM
type browserCookieSource interface {
	BrowserCookies() []http.Cookie
}
type GuacamoleFunc func(context.Context, protocol.GuacamoleOptions) (transport.Stats, error)
type WebFunc func(context.Context, protocol.WebPAM, protocol.WebOptions) (transport.Stats, error)
type DirectAdapters struct {
	WebSocket DirectFunc
	Guacamole GuacamoleFunc
	Web       WebFunc
}
type Target struct {
	AssetID, AccountID, BrowserURL, Activity, Username, Password string
	Interval                                                     time.Duration
	Cols, Rows                                                   int
	ConnectionOnly                                               bool
}
type Runner struct {
	pam       PAM
	browser   Browser
	metrics   Metrics
	targets   map[config.Protocol]Target
	direct    DirectFunc
	guacamole GuacamoleFunc
	web       WebFunc
}

func New(p PAM, b Browser, m Metrics, targets map[config.Protocol]Target, direct DirectFunc) *Runner {
	return NewWithAdapters(p, b, m, targets, DirectAdapters{WebSocket: direct})
}

func NewWithAdapters(p PAM, b Browser, m Metrics, targets map[config.Protocol]Target, adapters DirectAdapters) *Runner {
	if adapters.WebSocket == nil {
		adapters.WebSocket = transport.RunWebSocket
	}
	if adapters.Guacamole == nil {
		adapters.Guacamole = protocol.RunGuacamole
	}
	if adapters.Web == nil {
		adapters.Web = protocol.RunWeb
	}
	return &Runner{pam: p, browser: b, metrics: m, targets: targets, direct: adapters.WebSocket, guacamole: adapters.Guacamole, web: adapters.Web}
}

func (r *Runner) Run(parent context.Context, job session.Job) (session.Handle, error) {
	target, ok := r.targets[job.Protocol]
	if !ok {
		return nil, fmt.Errorf("target for %s is missing", job.Protocol)
	}
	if job.AssetID != "" {
		target.AssetID = job.AssetID
	}
	if job.AccountID != "" {
		target.AccountID = job.AccountID
	}
	if target.Interval <= 0 {
		target.Interval = time.Second
	}
	if target.Cols == 0 {
		target.Cols = 158
	}
	if target.Rows == 0 {
		target.Rows = 33
	}
	protocolName := string(job.Protocol)
	mode := job.Mode
	if mode == "" {
		if job.Protocol == config.SSH || job.Protocol == config.MySQL {
			mode = config.Direct
		} else {
			mode = config.Browser
		}
	}
	modeName := string(mode)
	start := time.Now()
	r.metrics.Started(protocolName, modeName)
	var connected atomic.Bool
	connectedSignal := make(chan struct{})
	var connectLatencyNanos atomic.Int64
	markConnected := func(latency time.Duration) {
		if latency <= 0 {
			latency = time.Since(start)
		}
		if latency <= 0 {
			latency = time.Nanosecond
		}
		if connected.CompareAndSwap(false, true) {
			connectLatencyNanos.Store(int64(latency))
			close(connectedSignal)
			r.metrics.Active(protocolName, modeName, 1)
			r.metrics.Connected(protocolName, modeName, latency)
		}
	}
	if _, err := r.pam.ReviewCandidates(parent, target.AssetID); err != nil {
		r.metrics.Failed(protocolName, modeName, "review")
		return nil, err
	}
	ctx, cancel := context.WithCancel(parent)
	h := &handle{cancel: cancel, done: make(chan session.Observation, 1), connected: connectedSignal}
	var run func() (transport.Stats, error)
	switch job.Protocol {
	case config.SSH:
		if mode != config.Direct {
			return nil, fmt.Errorf("ssh requires direct execution mode")
		}
		s, err := r.pam.CreateSession(parent, target.AssetID, target.AccountID, "native")
		if err != nil {
			return nil, err
		}
		var o transport.WebSocketOptions
		if target.ConnectionOnly {
			o, err = protocol.SSHConnectionOnlyOptions(r.pam.BaseURL(), s.ID, r.pam.Token(), target.Cols, target.Rows)
		} else {
			o, err = protocol.SSHOptions(r.pam.BaseURL(), s.ID, r.pam.Token(), target.Cols, target.Rows, target.Interval, target.Activity)
		}
		if err != nil {
			return nil, err
		}
		o.Headers = r.pam.WebSocketHeaders()
		o.AfterDial = func() error {
			if err := r.pam.Connect(ctx, s.ID); err != nil {
				return err
			}
			connectCtx, connectCancel := context.WithTimeout(ctx, pamSessionConnectTimeout)
			defer connectCancel()
			if _, err := r.pam.WaitConnected(connectCtx, s.ID, 250*time.Millisecond); err != nil {
				if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
					return fmt.Errorf("PAM session connect timeout: %w", err)
				}
				return err
			}
			markConnected(0)
			return nil
		}
		run = func() (transport.Stats, error) { return r.runSSHWithReconnect(ctx, s.ID, target, o) }
	case config.MySQL:
		if mode == config.Direct {
			s, err := r.pam.CreateDBSession(parent, target.AssetID, target.AccountID)
			if err != nil {
				return nil, err
			}
			o, err := protocol.MySQLOptions(r.pam.BaseURL(), s.ID, r.pam.Token(), target.Interval, target.Activity)
			if err != nil {
				return nil, err
			}
			o.Headers = r.pam.WebSocketHeaders()
			o.AfterDial = func() error { markConnected(0); return nil }
			run = func() (transport.Stats, error) { return r.direct(ctx, o) }
		} else if mode == config.Browser {
			if r.browser == nil {
				return nil, fmt.Errorf("browser pool is required")
			}
			url := expandBrowserURL(target.BrowserURL, target, protocolName)
			username, password, cookies := r.browserAuthentication(target)
			if target.Username != "" && target.Password != "" {
				username, password, cookies = target.Username, target.Password, nil
			}
			run = func() (transport.Stats, error) {
				result, err := r.browser.Run(ctx, browser.Job{ID: job.ID, Protocol: protocolName, URL: url, AssetID: target.AssetID, AccountID: target.AccountID, LoginURL: r.pam.BaseURL(), Username: username, Password: password, Cookies: cookies, OnConnected: markConnected})
				return transport.Stats{SentMessages: result.Heartbeats, LastActivity: result.LastActivity, PrepareLatency: result.PrepareLatency, EditorReadyLatency: result.EditorReadyLatency}, err
			}
		} else {
			return nil, fmt.Errorf("unsupported execution mode %s", mode)
		}
	case config.RDP, config.VNC:
		if mode == config.Direct {
			s, err := r.pam.CreateSession(parent, target.AssetID, target.AccountID, "guacd")
			if err != nil {
				return nil, err
			}
			o, err := protocol.GuacamoleTunnelOptions(r.pam.BaseURL(), s.ID, r.pam.WebSocketHeaders(), 1280, 720, 96, target.Interval, 15*time.Second)
			if err != nil {
				return nil, err
			}
			o.ConnectionOnly = target.ConnectionOnly
			o.AfterDial = func() error {
				if err := r.pam.Connect(ctx, s.ID); err != nil {
					return err
				}
				markConnected(0)
				return nil
			}
			run = func() (transport.Stats, error) { return r.guacamole(ctx, o) }
		} else if mode == config.Browser {
			if r.browser == nil {
				return nil, fmt.Errorf("browser pool is required")
			}
			url := expandBrowserURL(target.BrowserURL, target, protocolName)
			username, password, cookies := r.browserAuthentication(target)
			run = func() (transport.Stats, error) {
				result, err := r.browser.Run(ctx, browser.Job{ID: job.ID, Protocol: protocolName, URL: url, LoginURL: r.pam.BaseURL(), Username: username, Password: password, Cookies: cookies, OnConnected: markConnected})
				return transport.Stats{SentMessages: result.Heartbeats, LastActivity: result.LastActivity, PrepareLatency: result.PrepareLatency, EditorReadyLatency: result.EditorReadyLatency}, err
			}
		} else {
			return nil, fmt.Errorf("unsupported execution mode %s", mode)
		}
	case config.Web:
		if mode == config.Direct {
			o := protocol.WebOptions{AssetID: target.AssetID, AccountID: target.AccountID, Width: 1280, Height: 720, ActivityInterval: target.Interval, InactivityTimeout: 15 * time.Second, OnConnected: func() { markConnected(0) }}
			run = func() (transport.Stats, error) { return r.web(ctx, r.pam, o) }
		} else if mode == config.Browser {
			if r.browser == nil {
				return nil, fmt.Errorf("browser pool is required")
			}
			url := expandBrowserURL(target.BrowserURL, target, protocolName)
			username, password, cookies := r.browserAuthentication(target)
			run = func() (transport.Stats, error) {
				result, err := r.browser.Run(ctx, browser.Job{ID: job.ID, Protocol: protocolName, URL: url, LoginURL: r.pam.BaseURL(), Username: username, Password: password, Cookies: cookies, OnConnected: markConnected})
				return transport.Stats{SentMessages: result.Heartbeats, LastActivity: result.LastActivity, PrepareLatency: result.PrepareLatency, EditorReadyLatency: result.EditorReadyLatency}, err
			}
		} else {
			return nil, fmt.Errorf("unsupported execution mode %s", mode)
		}
	default:
		return nil, fmt.Errorf("unsupported protocol %s", job.Protocol)
	}
	go func() {
		stats, err := run()
		if err != nil {
			log.Printf("pam-loadtest session %d %s/%s asset=%s ended: err=%v ctxErr=%v connected=%v", job.ID, protocolName, modeName, target.AssetID, err, ctx.Err(), connected.Load())
		}
		if err != nil && !connected.Load() && ctx.Err() == nil && isGraphicalConnectTimeout(job.Protocol, err) {
			err = fmt.Errorf("graphical session connect timeout: %w", err)
		}
		if connected.Load() {
			r.metrics.Active(protocolName, modeName, -1)
		}
		r.metrics.Traffic(protocolName, modeName, stats.SentBytes, stats.ReceivedBytes)
		reason := session.Completed
		if err != nil {
			// Once the run context is cancelled (scenario teardown), any
			// concurrent transport error is teardown noise, not a runtime
			// failure. PAM may close the WebSocket a few milliseconds before
			// the agent observes ctx.Done(), and that race must not inflate
			// runtime_failures.
			if (ctx.Err() != nil && isTransportClosedError(err)) || cancellationOnly(err, ctx.Err()) {
				reason = session.Cancelled
			} else {
				reason = session.Failed
				r.metrics.Disconnected(protocolName, modeName, "runtime")
			}
		}
		h.done <- session.Observation{Reason: reason, Mode: mode, ConnectLatency: time.Duration(connectLatencyNanos.Load()), PrepareLatency: stats.PrepareLatency, EditorReadyLatency: stats.EditorReadyLatency, SentBytes: stats.SentBytes, ReceivedBytes: stats.ReceivedBytes, ActivityEvents: stats.SentMessages, LastActivity: stats.LastActivity, Err: err}
		close(h.done)
	}()
	return h, nil
}

func (r *Runner) runSSHWithReconnect(ctx context.Context, sessionID string, target Target, initial transport.WebSocketOptions) (transport.Stats, error) {
	options := initial
	var total transport.Stats
	for attempt := 0; ; attempt++ {
		stats, err := r.direct(ctx, options)
		total = mergeTransportStats(total, stats)
		if err == nil || ctx.Err() != nil || !isSSHTransportClosed(err) {
			return total, err
		}
		if attempt >= sshTransportReconnectAttempts {
			return total, fmt.Errorf("SSH transport reconnect attempts exhausted: %w", err)
		}
		if statusErr := r.waitForSSHSessionReconnect(ctx, sessionID); statusErr != nil {
			return total, fmt.Errorf("check PAM session before SSH transport reconnect: %w", statusErr)
		}
		backoff := sshTransportReconnectBackoff[attempt]
		select {
		case <-ctx.Done():
			return total, ctx.Err()
		case <-time.After(backoff):
		}
		options, err = protocol.SSHReconnectOptions(r.pam.BaseURL(), sessionID, r.pam.Token(), target.Cols, target.Rows, target.Interval, target.Activity)
		if err != nil {
			return total, err
		}
		options.Headers = r.pam.WebSocketHeaders()
	}
}

func (r *Runner) waitForSSHSessionReconnect(ctx context.Context, sessionID string) error {
	statusCtx, cancel := context.WithTimeout(ctx, sshTransportStateTimeout)
	defer cancel()
	for {
		current, err := r.pam.SessionStatus(statusCtx, sessionID)
		if err != nil {
			return err
		}
		switch current.Status {
		case "connected", "active":
			return nil
		case "connecting":
			select {
			case <-statusCtx.Done():
				return fmt.Errorf("PAM session remained connecting: %w", statusCtx.Err())
			case <-time.After(500 * time.Millisecond):
			}
		default:
			return fmt.Errorf("PAM session is %s", pam.Redact(current.Status))
		}
	}
}

func isSSHTransportClosed(err error) bool {
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "websocket read failed") || strings.Contains(message, "websocket write failed")
}

// isTransportClosedError reports whether err is a transport-level close
// (WebSocket failure, reset, EOF or broken pipe), matching the runreport
// "transport_closed" category. Such errors racing scenario teardown are
// classified as cancelled rather than runtime failures.
func isTransportClosedError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "websocket") ||
		strings.Contains(message, "unexpected eof") ||
		strings.Contains(message, "connection reset") ||
		strings.Contains(message, "broken pipe")
}

func mergeTransportStats(total, next transport.Stats) transport.Stats {
	total.SentMessages += next.SentMessages
	total.ReceivedMessages += next.ReceivedMessages
	total.SentBytes += next.SentBytes
	total.ReceivedBytes += next.ReceivedBytes
	if next.LastActivity.After(total.LastActivity) {
		total.LastActivity = next.LastActivity
	}
	if total.PrepareLatency == 0 {
		total.PrepareLatency = next.PrepareLatency
	}
	if total.EditorReadyLatency == 0 {
		total.EditorReadyLatency = next.EditorReadyLatency
	}
	return total
}

func isGraphicalConnectTimeout(protocol config.Protocol, err error) bool {
	if protocol != config.RDP && protocol != config.VNC && protocol != config.Web && protocol != config.MySQL {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "timeout") || strings.Contains(message, "timed out")
}

func cancellationOnly(err, contextErr error) bool {
	if err == nil || contextErr == nil {
		return false
	}
	var cleanupErr *protocol.CleanupError
	if errors.As(err, &cleanupErr) {
		return false
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		children := joined.Unwrap()
		if len(children) == 0 {
			return false
		}
		for _, child := range children {
			if !cancellationOnly(child, contextErr) {
				return false
			}
		}
		return true
	}
	return errors.Is(err, contextErr)
}

func (r *Runner) browserAuthentication(target Target) (string, string, []browser.Cookie) {
	source, ok := r.pam.(browserCookieSource)
	if !ok {
		return target.Username, target.Password, nil
	}
	stored := source.BrowserCookies()
	if len(stored) == 0 {
		return target.Username, target.Password, nil
	}
	cookieURL := r.pam.BaseURL()
	if parsed, err := url.Parse(cookieURL); err == nil && parsed.Scheme != "" && parsed.Host != "" {
		cookieURL = parsed.Scheme + "://" + parsed.Host
	}
	cookies := make([]browser.Cookie, 0, len(stored))
	for _, cookie := range stored {
		if cookie.Name != "" {
			cookies = append(cookies, browser.Cookie{Name: cookie.Name, Value: cookie.Value, URL: cookieURL})
		}
	}
	if len(cookies) == 0 {
		return target.Username, target.Password, nil
	}
	return "", "", cookies
}

func expandBrowserURL(template string, target Target, protocol string) string {
	replacer := strings.NewReplacer("{assetId}", url.QueryEscape(target.AssetID), "{accountId}", url.QueryEscape(target.AccountID), "{protocol}", url.QueryEscape(protocol))
	return replacer.Replace(template)
}

type handle struct {
	cancel    context.CancelFunc
	done      chan session.Observation
	connected <-chan struct{}
	once      sync.Once
}

func (h *handle) Close() error               { h.once.Do(h.cancel); return nil }
func (h *handle) Connected() <-chan struct{} { return h.connected }
func (h *handle) Wait(ctx context.Context) session.Observation {
	select {
	case observation := <-h.done:
		return observation
	case <-ctx.Done():
		return session.Observation{Reason: session.Cancelled, Err: ctx.Err()}
	}
}
