package app

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"pam-loadtest/internal/allocation"
	"pam-loadtest/internal/browser"
	"pam-loadtest/internal/config"
	"pam-loadtest/internal/engine"
	"pam-loadtest/internal/inventory"
	loadmetrics "pam-loadtest/internal/metrics"
	"pam-loadtest/internal/pam"
	"pam-loadtest/internal/runreport"
	"pam-loadtest/internal/scheduler"
	"pam-loadtest/internal/session"
)

type LocalOptions struct {
	MetricsListen, NodeExecutable, WorkerScript       string
	PAMToken                                          string
	PAMCookies                                        []http.Cookie
	BrowserWorkers, SessionsPerWorker, DirectCapacity int
	StopPolicy                                        loadmetrics.StopPolicy
}

func sshContinuousActivity(interval time.Duration) string {
	if interval < time.Second {
		interval = time.Second
	}
	return fmt.Sprintf("while true; do printf 'pam-loadtest %%s\\n' \"$(date +%%s%%N)\"; sleep %d; done", int(interval/time.Second))
}

func sshActivity(mode string, interval time.Duration) string {
	if mode == "keepalive" {
		return "true"
	}
	return sshContinuousActivity(interval)
}

func buildTargets(cfg config.Config) (map[config.Protocol]engine.Target, error) {
	targets := map[config.Protocol]engine.Target{}
	for protocol, count := range cfg.Protocols {
		if count == 0 {
			continue
		}
		asset, account, urlTemplate, err := cfg.Asset(protocol)
		if err != nil {
			return nil, err
		}
		target := engine.Target{AssetID: asset, AccountID: account, BrowserURL: urlTemplate, Interval: cfg.ActivityInterval(protocol), ConnectionOnly: cfg.ConnectionOnly}
		switch protocol {
		case config.SSH:
			target.Activity = sshActivity(cfg.SSHActivityMode, cfg.SSHActivityInterval)
		case config.MySQL:
			target.Activity = "SELECT COUNT(*), MAX(id) FROM pam_loadtest.payload"
			if target.BrowserURL == "" {
				target.BrowserURL = strings.TrimRight(cfg.PAM.BaseURL, "/") + "/#/asset"
			}
		case config.RDP, config.VNC:
			if target.BrowserURL == "" {
				target.BrowserURL = strings.TrimRight(cfg.PAM.BaseURL, "/") + "/#/access?assetId={assetId}&protocol={protocol}&accountId={accountId}"
			}
		case config.Web:
			if target.BrowserURL == "" {
				target.BrowserURL = strings.TrimRight(cfg.PAM.BaseURL, "/") + "/#/web-access?assetId={assetId}&accountId={accountId}"
			}
		}
		targets[protocol] = target
	}
	return targets, nil
}

func buildBoundTargets(cfg config.Config) (map[config.Protocol]engine.Target, error) {
	targets := map[config.Protocol]engine.Target{}
	for protocol, count := range cfg.Protocols {
		if count == 0 {
			continue
		}
		target := engine.Target{Interval: cfg.ActivityInterval(protocol), ConnectionOnly: cfg.ConnectionOnly}
		mapping := cfg.Assets[protocol]
		if mapping.URLTemplateEnv != "" {
			target.BrowserURL = os.Getenv(mapping.URLTemplateEnv)
		}
		switch protocol {
		case config.SSH:
			target.Activity = sshActivity(cfg.SSHActivityMode, cfg.SSHActivityInterval)
		case config.MySQL:
			target.Activity = "SELECT COUNT(*), MAX(id) FROM pam_loadtest.payload"
			if target.BrowserURL == "" {
				target.BrowserURL = strings.TrimRight(cfg.PAM.BaseURL, "/") + "/#/asset"
			}
		case config.RDP, config.VNC:
			if target.BrowserURL == "" {
				target.BrowserURL = strings.TrimRight(cfg.PAM.BaseURL, "/") + "/#/access?assetId={assetId}&protocol={protocol}&accountId={accountId}"
			}
		case config.Web:
			if target.BrowserURL == "" {
				target.BrowserURL = strings.TrimRight(cfg.PAM.BaseURL, "/") + "/#/web-access?assetId={assetId}&accountId={accountId}"
			}
		default:
			return nil, fmt.Errorf("unsupported protocol %s", protocol)
		}
		targets[protocol] = target
	}
	return targets, nil
}

func prepareManifestJobs(jobs []config.Job, path string, seed int64) ([]config.Job, error) {
	manifest, err := inventory.LoadManifest(path)
	if err != nil {
		return nil, err
	}
	bound, _, err := allocation.Bind(jobs, manifest, seed)
	return bound, err
}

func validateBrowserCapacity(cfg config.Config, workers, sessionsPerWorker int) error {
	needed := browserSessions(cfg)
	if needed > workers*sessionsPerWorker {
		return fmt.Errorf("browser capacity %d is below %d graphical sessions", workers*sessionsPerWorker, needed)
	}
	return nil
}

func browserSessions(cfg config.Config) int {
	needed := 0
	for _, protocol := range []config.Protocol{config.RDP, config.VNC, config.Web, config.MySQL} {
		if modes, explicit := cfg.ExecutionModes[protocol]; explicit {
			needed += modes.Browser
		} else {
			needed += cfg.Protocols[protocol]
		}
	}
	return needed
}

func applyBrowserCredentials(targets map[config.Protocol]engine.Target, username, password string) {
	for _, protocol := range []config.Protocol{config.RDP, config.VNC, config.Web, config.MySQL} {
		target, ok := targets[protocol]
		if ok {
			target.Username = username
			target.Password = password
			targets[protocol] = target
		}
	}
}

func runtimeDuration(cfg config.Config) time.Duration { return cfg.Ramp + cfg.Hold }

func applyRuntimeOverrides(cfg *config.Config) error {
	if value := os.Getenv("PAM_RAMP_OVERRIDE"); value != "" {
		d, err := time.ParseDuration(value)
		if err != nil || d <= 0 {
			return fmt.Errorf("PAM_RAMP_OVERRIDE must be a positive duration")
		}
		cfg.Ramp = d
	}
	if value := os.Getenv("PAM_HOLD_OVERRIDE"); value != "" {
		d, err := time.ParseDuration(value)
		if err != nil || d <= 0 {
			return fmt.Errorf("PAM_HOLD_OVERRIDE must be a positive duration")
		}
		cfg.Hold = d
	}
	value := os.Getenv("PAM_TOTAL_OVERRIDE")
	total := cfg.Total
	if value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 {
			return fmt.Errorf("PAM_TOTAL_OVERRIDE must be a positive integer")
		}
		total = parsed
	}
	if selected := config.Protocol(os.Getenv("PAM_PROTOCOL_OVERRIDE")); selected != "" {
		known := false
		for _, protocol := range []config.Protocol{config.SSH, config.RDP, config.VNC, config.Web, config.MySQL} {
			if selected == protocol {
				known = true
				break
			}
		}
		if !known {
			return fmt.Errorf("PAM_PROTOCOL_OVERRIDE is invalid")
		}
		originalCount := cfg.Protocols[selected]
		originalModes, explicitModes := cfg.ExecutionModes[selected]
		cfg.Total = total
		cfg.Protocols = map[config.Protocol]int{selected: total}
		if explicitModes {
			cfg.ExecutionModes = map[config.Protocol]config.ModeCounts{selected: scaleModeCounts(originalModes, originalCount, total)}
		} else {
			cfg.ExecutionModes = nil
		}
		return nil
	}
	if value == "" {
		return nil
	}
	if cfg.Total < 1 {
		return fmt.Errorf("base scenario total must be positive")
	}
	type remainder struct {
		protocol config.Protocol
		fraction float64
		order    int
	}
	order := []config.Protocol{config.SSH, config.RDP, config.VNC, config.Web, config.MySQL}
	scaled := map[config.Protocol]int{}
	remainders := make([]remainder, 0, len(order))
	assigned := 0
	for index, protocol := range order {
		exact := float64(cfg.Protocols[protocol]) * float64(total) / float64(cfg.Total)
		whole := int(exact)
		scaled[protocol] = whole
		assigned += whole
		remainders = append(remainders, remainder{protocol: protocol, fraction: exact - float64(whole), order: index})
	}
	sort.SliceStable(remainders, func(i, j int) bool {
		if remainders[i].fraction == remainders[j].fraction {
			return remainders[i].order < remainders[j].order
		}
		return remainders[i].fraction > remainders[j].fraction
	})
	for i := 0; i < total-assigned; i++ {
		scaled[remainders[i%len(remainders)].protocol]++
	}
	originalProtocols := cfg.Protocols
	originalModes := cfg.ExecutionModes
	cfg.Total = total
	cfg.Protocols = scaled
	if len(originalModes) > 0 {
		cfg.ExecutionModes = make(map[config.Protocol]config.ModeCounts, len(originalModes))
		for protocol, modes := range originalModes {
			cfg.ExecutionModes[protocol] = scaleModeCounts(modes, originalProtocols[protocol], scaled[protocol])
		}
	}
	return nil
}

func scaleModeCounts(original config.ModeCounts, originalTotal, targetTotal int) config.ModeCounts {
	if originalTotal <= 0 || targetTotal <= 0 {
		return config.ModeCounts{}
	}
	browserExact := float64(original.Browser) * float64(targetTotal) / float64(originalTotal)
	directExact := float64(original.Direct) * float64(targetTotal) / float64(originalTotal)
	result := config.ModeCounts{Browser: int(browserExact), Direct: int(directExact)}
	for result.Browser+result.Direct < targetTotal {
		browserRemainder := browserExact - float64(result.Browser)
		directRemainder := directExact - float64(result.Direct)
		if browserRemainder >= directRemainder {
			result.Browser++
		} else {
			result.Direct++
		}
	}
	return result
}

func RunLocal(parent context.Context, configPath string, opts LocalOptions) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	if err := applyRuntimeOverrides(&cfg); err != nil {
		return err
	}
	if path := os.Getenv("PAM_ASSET_MANIFEST"); path != "" {
		_, err = runLocalReport(parent, cfg, path, opts)
		return err
	}
	return RunConfig(parent, cfg, opts)
}

func RunLocalReport(parent context.Context, configPath string, opts LocalOptions) (runreport.Report, error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		return runreport.Report{}, err
	}
	if err := applyRuntimeOverrides(&cfg); err != nil {
		return runreport.Report{}, err
	}
	path := os.Getenv("PAM_ASSET_MANIFEST")
	if path == "" {
		return runreport.Report{}, fmt.Errorf("PAM_ASSET_MANIFEST is required for report mode")
	}
	return runLocalReport(parent, cfg, path, opts)
}

func runLocalReport(parent context.Context, cfg config.Config, path string, opts LocalOptions) (runreport.Report, error) {
	jobs, err := cfg.Expand()
	if err != nil {
		return runreport.Report{}, err
	}
	jobs, err = prepareManifestJobs(jobs, path, cfg.Seed)
	if err != nil {
		return runreport.Report{}, err
	}
	return RunConfigJobs(parent, cfg, jobs, cfg.Name, opts)
}

func RunConfig(parent context.Context, cfg config.Config, opts LocalOptions) error {
	jobs, err := cfg.Expand()
	if err != nil {
		return err
	}
	return runConfigJobs(parent, cfg, jobs, opts, false, nil)
}

func RunConfigJobs(parent context.Context, cfg config.Config, jobs []config.Job, runID string, opts LocalOptions) (runreport.Report, error) {
	tracker, err := runreport.NewTrackerWithBuildVersion(runID, BuildVersion, jobs)
	if err != nil {
		return runreport.Report{}, err
	}
	err = runConfigJobs(parent, cfg, jobs, opts, true, tracker)
	if err != nil {
		log.Printf("pam-loadtest run %s failed: %v", runID, err)
	}
	status := "completed"
	if err != nil {
		status = "failed"
		if errors.Is(err, context.Canceled) {
			status = "cancelled"
		}
	}
	report := tracker.Snapshot(status)
	if err == nil {
		err = terminalEvidenceError(report)
		if err != nil {
			report.Status = "failed"
		}
	}
	return report, err
}

func terminalEvidenceError(report runreport.Report) error {
	counts := report.Totals
	if report.Status != "completed" || counts.Planned != counts.Used || counts.Unused != 0 || counts.Duplicates != 0 || counts.StartFailures != 0 || counts.RuntimeFailures != 0 || counts.Started != counts.Planned || counts.Maintained != counts.Started {
		return fmt.Errorf("run terminal evidence failed: planned=%d used=%d started=%d maintained=%d unused=%d duplicates=%d start_failures=%d runtime_failures=%d", counts.Planned, counts.Used, counts.Started, counts.Maintained, counts.Unused, counts.Duplicates, counts.StartFailures, counts.RuntimeFailures)
	}
	return nil
}

func runConfigJobs(parent context.Context, cfg config.Config, jobs []config.Job, opts LocalOptions, bound bool, tracker *runreport.Tracker) error {
	username, password, err := cfg.Credentials()
	if err != nil {
		return err
	}
	var targets map[config.Protocol]engine.Target
	if bound {
		targets, err = buildBoundTargets(cfg)
	} else {
		targets, err = buildTargets(cfg)
	}
	if err != nil {
		return err
	}
	applyBrowserCredentials(targets, username, password)
	graphical := browserSessions(cfg)
	if opts.BrowserWorkers <= 0 {
		if graphical > 0 {
			opts.BrowserWorkers = 1
		}
	}
	if opts.SessionsPerWorker <= 0 {
		opts.SessionsPerWorker = 50
	}
	if err := validateBrowserCapacity(cfg, opts.BrowserWorkers, opts.SessionsPerWorker); err != nil {
		return err
	}
	client, err := pam.New(cfg.PAM.BaseURL, pam.Options{Token: opts.PAMToken, Cookies: opts.PAMCookies})
	if err != nil {
		return err
	}
	if opts.PAMToken == "" && len(opts.PAMCookies) == 0 {
		if err := client.Login(parent, username, password); err != nil {
			return err
		}
	} else if opts.PAMToken != "" && client.Token() == "" {
		return fmt.Errorf("PAM runtime token is empty")
	}
	username = ""
	password = ""
	registry := prometheus.NewRegistry()
	measurements := loadmetrics.New(registry)
	var server *http.Server
	if opts.MetricsListen != "" {
		server = &http.Server{Addr: opts.MetricsListen, Handler: promhttp.HandlerFor(registry, promhttp.HandlerOpts{}), ReadHeaderTimeout: 5 * time.Second}
		go func() { _ = server.ListenAndServe() }()
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = server.Shutdown(ctx)
		}()
	}
	var pool *browser.Pool
	if graphical > 0 {
		if opts.NodeExecutable == "" {
			opts.NodeExecutable = "node"
		}
		if opts.WorkerScript == "" {
			opts.WorkerScript = filepath.Join("browser-worker", "worker.mjs")
		}
		pool = browser.NewPoolWithCapacity(opts.BrowserWorkers, opts.SessionsPerWorker, func(int) (browser.Client, error) {
			return browser.NewProcessClient(opts.NodeExecutable, opts.WorkerScript)
		})
		defer pool.Close()
	}
	var runner session.Runner = engine.New(client, pool, measurements, targets, nil)
	if tracker != nil {
		runner = &reportingRunner{inner: runner, tracker: tracker}
	}
	runCtx, cancel := context.WithTimeout(parent, runtimeDuration(cfg))
	defer cancel()
	opts.StopPolicy = effectiveStopPolicy(cfg, opts.StopPolicy)
	var stopMu sync.Mutex
	stopReason := ""
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-runCtx.Done():
				return
			case <-ticker.C:
				if stop, reason := opts.StopPolicy.Evaluate(measurements.Snapshot()); stop {
					stopMu.Lock()
					stopReason = reason
					stopMu.Unlock()
					cancel()
					return
				}
			}
		}
	}()
	err = scheduler.RunWithRetries(runCtx, scheduler.Plan(jobs, cfg.Ramp, cfg.Seed, .10), runner, realClockAdapter{}, scheduler.ConnectRetryPolicy{MaxRetries: cfg.ConnectRetries, Backoffs: []time.Duration{2 * time.Second, 5 * time.Second, 10 * time.Second}})
	stopMu.Lock()
	reason := stopReason
	stopMu.Unlock()
	if reason != "" {
		return fmt.Errorf("automatic stop: %s", reason)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return nil
	}
	return err
}

func defaultStopPolicy(total int) loadmetrics.StopPolicy {
	minimum := int64(100)
	if total < 100 {
		minimum = 1
	}
	return loadmetrics.StopPolicy{MinAttempts: minimum, MaxFailureRate: .01, MaxDisconnectRate: .01}
}

func effectiveStopPolicy(cfg config.Config, configured loadmetrics.StopPolicy) loadmetrics.StopPolicy {
	if cfg.ContinueOnErrors {
		return loadmetrics.StopPolicy{MinAttempts: 1<<63 - 1, MaxFailureRate: 1, MaxDisconnectRate: 1}
	}
	if configured.MinAttempts == 0 {
		return defaultStopPolicy(cfg.Total)
	}
	return configured
}

type reportingRunner struct {
	inner   session.Runner
	tracker *runreport.Tracker
	mu      sync.Mutex
	seen    map[string]struct{}
}

func (r *reportingRunner) Run(ctx context.Context, job session.Job) (session.Handle, error) {
	bound := config.Job{ID: job.ID, Protocol: job.Protocol, Mode: job.Mode, AssetID: job.AssetID, AccountID: job.AccountID}
	r.mu.Lock()
	if r.seen == nil {
		r.seen = make(map[string]struct{})
	}
	if _, seen := r.seen[bound.AssetID]; !seen {
		r.seen[bound.AssetID] = struct{}{}
		r.tracker.Attempt(bound)
	}
	r.mu.Unlock()
	handle, err := r.inner.Run(ctx, job)
	if err != nil {
		r.tracker.StartFailed(bound, err)
		return nil, err
	}
	return &reportingHandle{Handle: handle, job: bound, tracker: r.tracker}, nil
}

type reportingHandle struct {
	session.Handle
	job            config.Job
	tracker        *runreport.Tracker
	once           sync.Once
	closeRequested atomic.Bool
	closeAtNanos   atomic.Int64
}

func (h *reportingHandle) Close() error {
	h.closeRequested.Store(true)
	h.closeAtNanos.Store(time.Now().UnixNano())
	return h.Handle.Close()
}

func (h *reportingHandle) Wait(ctx context.Context) session.Observation {
	observation := h.Observe(ctx)
	h.Finalize(observation, true)
	return observation
}

func (h *reportingHandle) Observe(ctx context.Context) session.Observation { return h.Handle.Wait(ctx) }
func (h *reportingHandle) Connected() <-chan struct{} {
	if aware, ok := h.Handle.(session.ConnectionAware); ok {
		return aware.Connected()
	}
	return nil
}
func (h *reportingHandle) ConnectRetry()          { h.tracker.ConnectRetry(h.job) }
func (h *reportingHandle) ConnectRetrySucceeded() { h.tracker.ConnectRetrySucceeded(h.job) }
func (h *reportingHandle) ConnectRetryExhausted() { h.tracker.ConnectRetryExhausted(h.job) }
func (h *reportingHandle) Finalize(observation session.Observation, connected bool) {
	h.once.Do(func() {
		h.tracker.Record(h.job, observation)
		if !connected {
			h.tracker.StartFailed(h.job, observation.Err)
			return
		}
		h.tracker.Started(h.job)
		completedAtShutdown := false
		if observation.Reason == session.Completed && h.closeRequested.Load() {
			closedAt := time.Unix(0, h.closeAtNanos.Load())
			completedAtShutdown = !observation.LastActivity.After(closedAt) && closedAt.Sub(observation.LastActivity) <= 5*time.Second
		}
		invalid := observation.Reason == session.Failed || (observation.Reason == session.Completed && !completedAtShutdown) || observation.ConnectLatency <= 0 || observation.ActivityEvents <= 0 || observation.LastActivity.IsZero()
		if h.job.Mode == config.Direct && (observation.SentBytes <= 0 || observation.ReceivedBytes <= 0) {
			invalid = true
		}
		if invalid {
			h.tracker.RuntimeFailed(h.job, observation.Err)
		} else {
			h.tracker.Maintained(h.job)
		}
	})
}

type realClockAdapter struct{}

func (realClockAdapter) Now() time.Time                         { return time.Now() }
func (realClockAdapter) After(d time.Duration) <-chan time.Time { return time.After(d) }
