package app

import (
	"context"
	"errors"
	"os"
	"pam-loadtest/internal/config"
	"pam-loadtest/internal/engine"
	"pam-loadtest/internal/inventory"
	loadmetrics "pam-loadtest/internal/metrics"
	"pam-loadtest/internal/runreport"
	"pam-loadtest/internal/session"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPrepareManifestJobsBindsBeforeRuntime(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manifest.json")
	manifest := inventory.Manifest{Version: 1, Assets: []inventory.ManifestAsset{
		{Name: "one", IP: "10.1.0.1", Protocol: "ssh", AssetID: "a-1", AccountID: "u-1"},
		{Name: "two", IP: "10.1.0.2", Protocol: "ssh", AssetID: "a-2", AccountID: "u-2"},
	}}
	if err := inventory.WriteManifest(path, manifest); err != nil {
		t.Fatal(err)
	}
	jobs := []config.Job{{ID: 1, Protocol: config.SSH}, {ID: 2, Protocol: config.SSH}}
	bound, err := prepareManifestJobs(jobs, path, 42)
	if err != nil {
		t.Fatal(err)
	}
	if bound[0].AssetID == "" || bound[1].AssetID == "" || bound[0].AssetID == bound[1].AssetID {
		t.Fatalf("jobs=%+v", bound)
	}
}

func TestRunLocalRejectsExhaustedManifestBeforeCredentialsOrNetwork(t *testing.T) {
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "manifest.json")
	manifest := inventory.Manifest{Version: 1, Assets: []inventory.ManifestAsset{{Name: "one", IP: "10.1.0.1", Protocol: "ssh", AssetID: "a-1", AccountID: "u-1"}}}
	if err := inventory.WriteManifest(manifestPath, manifest); err != nil {
		t.Fatal(err)
	}
	scenarioPath := filepath.Join(dir, "scenario.yaml")
	body := `name: two
total: 2
ramp: 1m
hold: 1m
seed: 42
protocols: {ssh: 2}
pam: {base_url: http://127.0.0.1:1, username_env: MISSING_USER, password_env: MISSING_PASS}
assets: {ssh: {asset_id_env: SSH_ASSET, account_id_env: SSH_ACCOUNT}}
`
	if err := os.WriteFile(scenarioPath, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PAM_ASSET_MANIFEST", manifestPath)
	err := RunLocal(context.Background(), scenarioPath, LocalOptions{})
	if err == nil || !strings.Contains(err.Error(), "asset pool exhausted") {
		t.Fatalf("err=%v", err)
	}
}

func TestBuildBoundTargetsDoesNotRequireLegacyAssetEnvironment(t *testing.T) {
	cfg := config.Config{PAM: config.PAM{BaseURL: "http://pam.test"}, Protocols: map[config.Protocol]int{config.RDP: 1}, Assets: map[config.Protocol]config.Asset{config.RDP: {URLTemplateEnv: "RDP_URL"}}}
	t.Setenv("RDP_URL", "http://pam.test/{assetId}/{accountId}")
	targets, err := buildBoundTargets(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if targets[config.RDP].AssetID != "" || targets[config.RDP].BrowserURL == "" {
		t.Fatalf("target=%+v", targets[config.RDP])
	}
}

func TestBuildTargetsUsesRuntimeAssetEnvironmentAndSafeActivity(t *testing.T) {
	t.Setenv("SSH_ASSET", "a")
	t.Setenv("SSH_ACCOUNT", "u")
	cfg := config.Config{Protocols: map[config.Protocol]int{config.SSH: 1}, Assets: map[config.Protocol]config.Asset{config.SSH: {AssetIDEnv: "SSH_ASSET", AccountIDEnv: "SSH_ACCOUNT"}}}
	targets, err := buildTargets(cfg)
	if err != nil {
		t.Fatal(err)
	}
	target := targets[config.SSH]
	if target.AssetID != "a" || target.AccountID != "u" || target.Activity == "" || target.Interval <= 0 {
		t.Fatalf("target=%+v", target)
	}
}

func TestSSHActivityStartsOneContinuousOutputCommand(t *testing.T) {
	cfg := config.Config{Protocols: map[config.Protocol]int{config.SSH: 1}, SSHActivityInterval: time.Second}
	targets, err := buildBoundTargets(cfg)
	if err != nil {
		t.Fatal(err)
	}
	activity := targets[config.SSH].Activity
	if !strings.HasPrefix(activity, "while true; do ") || !strings.Contains(activity, "; sleep 1; done") {
		t.Fatalf("SSH activity must be one continuous output command, got %q", activity)
	}
}

func TestSSHContinuousActivityUsesConfiguredWholeSeconds(t *testing.T) {
	got := sshContinuousActivity(5 * time.Second)
	want := `while true; do printf 'pam-loadtest %s\n' "$(date +%s%N)"; sleep 5; done`
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	cfg := config.Config{Protocols: map[config.Protocol]int{config.SSH: 1}, SSHActivityInterval: 5 * time.Second}
	targets, err := buildBoundTargets(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if targets[config.SSH].Activity != want {
		t.Fatalf("target activity=%q", targets[config.SSH].Activity)
	}
}

func TestSSHKeepaliveActivityCompletesSoPeriodicInputCanReachShell(t *testing.T) {
	if got := sshActivity("keepalive", 10*time.Second); got != "true" {
		t.Fatalf("keepalive activity=%q", got)
	}
}

func TestBuildTargetsUsesVerifiedFrontendBrowserRoutes(t *testing.T) {
	t.Setenv("RDP_ASSET", "a id")
	t.Setenv("RDP_ACCOUNT", "u id")
	cfg := config.Config{PAM: config.PAM{BaseURL: "http://pam.test/"}, Protocols: map[config.Protocol]int{config.RDP: 1}, Assets: map[config.Protocol]config.Asset{config.RDP: {AssetIDEnv: "RDP_ASSET", AccountIDEnv: "RDP_ACCOUNT"}}}
	targets, err := buildTargets(cfg)
	if err != nil {
		t.Fatal(err)
	}
	want := "http://pam.test/#/access?assetId={assetId}&protocol={protocol}&accountId={accountId}"
	if targets[config.RDP].BrowserURL != want {
		t.Fatalf("url=%q", targets[config.RDP].BrowserURL)
	}
}

func TestBuildTargetsDefaultsMySQLBrowserURLToAssetList(t *testing.T) {
	t.Setenv("MYSQL_ASSET", "asset")
	t.Setenv("MYSQL_ACCOUNT", "account")
	cfg := config.Config{
		PAM:       config.PAM{BaseURL: "http://pam.test/"},
		Protocols: map[config.Protocol]int{config.MySQL: 1},
		Assets:    map[config.Protocol]config.Asset{config.MySQL: {AssetIDEnv: "MYSQL_ASSET", AccountIDEnv: "MYSQL_ACCOUNT"}},
	}
	targets, err := buildTargets(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if targets[config.MySQL].BrowserURL != "http://pam.test/#/asset" {
		t.Fatalf("mysql browser URL=%q", targets[config.MySQL].BrowserURL)
	}
}

func TestBuildBoundTargetsDefaultsMySQLBrowserURLToAssetList(t *testing.T) {
	cfg := config.Config{
		PAM:       config.PAM{BaseURL: "http://pam.test/"},
		Protocols: map[config.Protocol]int{config.MySQL: 1},
		Assets:    map[config.Protocol]config.Asset{config.MySQL: {}},
	}
	targets, err := buildBoundTargets(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if targets[config.MySQL].BrowserURL != "http://pam.test/#/asset" {
		t.Fatalf("mysql bound browser URL=%q", targets[config.MySQL].BrowserURL)
	}
}

func TestRunLocalRejectsMissingCredentialsBeforeNetwork(t *testing.T) {
	p := filepath.Join(t.TempDir(), "scenario.yaml")
	body := `name: one
total: 1
ramp: 1m
hold: 1m
protocols: {ssh: 1}
pam: {base_url: http://127.0.0.1:1, username_env: MISSING_USER, password_env: MISSING_PASS}
assets: {ssh: {asset_id_env: SSH_ASSET, account_id_env: SSH_ACCOUNT}}
`
	if err := os.WriteFile(p, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	err := RunLocal(context.Background(), p, LocalOptions{})
	if err == nil || !strings.Contains(err.Error(), "credential environment") {
		t.Fatalf("err=%v", err)
	}
}

func TestRuntimeOverridesRampAndScalesProtocolMix(t *testing.T) {
	t.Setenv("PAM_RAMP_OVERRIDE", "5m")
	t.Setenv("PAM_HOLD_OVERRIDE", "2m")
	t.Setenv("PAM_TOTAL_OVERRIDE", "1500")
	cfg := config.Config{Total: 1000, Ramp: 10 * time.Minute, Protocols: map[config.Protocol]int{config.SSH: 400, config.RDP: 200, config.VNC: 200, config.Web: 100, config.MySQL: 100}}
	if err := applyRuntimeOverrides(&cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Ramp != 5*time.Minute || cfg.Hold != 2*time.Minute || cfg.Total != 1500 || cfg.Protocols[config.SSH] != 600 || cfg.Protocols[config.RDP] != 300 || cfg.Protocols[config.Web] != 150 {
		t.Fatalf("cfg=%+v", cfg)
	}
}

func TestRuntimeOverridesScaleExecutionModesWithProtocolMix(t *testing.T) {
	t.Setenv("PAM_TOTAL_OVERRIDE", "100")
	cfg := config.Config{
		Total:          1000,
		Protocols:      map[config.Protocol]int{config.RDP: 500, config.VNC: 150, config.Web: 250, config.MySQL: 100},
		ExecutionModes: map[config.Protocol]config.ModeCounts{config.RDP: {Browser: 18, Direct: 482}, config.VNC: {Browser: 5, Direct: 145}, config.Web: {Browser: 9, Direct: 241}, config.MySQL: {Direct: 100}},
	}
	if err := applyRuntimeOverrides(&cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := cfg.Expand(); err != nil {
		t.Fatal(err)
	}
	for protocol, count := range cfg.Protocols {
		modes := cfg.ExecutionModes[protocol]
		if modes.Browser+modes.Direct != count {
			t.Fatalf("%s modes=%+v protocol=%d", protocol, modes, count)
		}
	}
}

func TestRuntimeOverridesRejectInvalidDuration(t *testing.T) {
	t.Setenv("PAM_RAMP_OVERRIDE", "fast")
	cfg := config.Config{Total: 1, Protocols: map[config.Protocol]int{config.SSH: 1}}
	if err := applyRuntimeOverrides(&cfg); err == nil {
		t.Fatal("expected invalid ramp override")
	}
}

func TestRuntimeOverrideSelectsOneProtocol(t *testing.T) {
	t.Setenv("PAM_TOTAL_OVERRIDE", "1")
	t.Setenv("PAM_PROTOCOL_OVERRIDE", "mysql")
	cfg := config.Config{Total: 1000, Protocols: map[config.Protocol]int{config.RDP: 400, config.VNC: 200, config.Web: 200, config.MySQL: 200}}
	if err := applyRuntimeOverrides(&cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Protocols[config.MySQL] != 1 || len(cfg.Protocols) != 1 {
		t.Fatalf("protocols=%v", cfg.Protocols)
	}
}

func TestBrowserCapacityCountsOnlyBrowserModeSessions(t *testing.T) {
	cfg := config.Config{
		Protocols: map[config.Protocol]int{config.RDP: 500, config.VNC: 150, config.Web: 250},
		ExecutionModes: map[config.Protocol]config.ModeCounts{
			config.RDP: {Browser: 18, Direct: 482}, config.VNC: {Browser: 5, Direct: 145}, config.Web: {Browser: 9, Direct: 241},
		},
	}
	if err := validateBrowserCapacity(cfg, 31, 1); err == nil {
		t.Fatal("31 slots must not cover 32 browser sessions")
	}
	if err := validateBrowserCapacity(cfg, 4, 8); err != nil {
		t.Fatal(err)
	}
}

func TestBrowserCapacityCountsMySQLBrowserSessions(t *testing.T) {
	cfg := config.Config{
		Protocols:      map[config.Protocol]int{config.MySQL: 1},
		ExecutionModes: map[config.Protocol]config.ModeCounts{config.MySQL: {Browser: 1}},
	}
	if err := validateBrowserCapacity(cfg, 0, 1); err == nil {
		t.Fatal("mysql browser session requires browser capacity")
	}
	if err := validateBrowserCapacity(cfg, 1, 1); err != nil {
		t.Fatal(err)
	}
}

func TestApplyBrowserCredentialsIncludesMySQL(t *testing.T) {
	targets := map[config.Protocol]engine.Target{
		config.RDP:   {},
		config.MySQL: {},
		config.SSH:   {},
	}
	applyBrowserCredentials(targets, "runtime-user", "runtime-pass")
	for _, protocol := range []config.Protocol{config.RDP, config.MySQL} {
		target := targets[protocol]
		if target.Username != "runtime-user" || target.Password != "runtime-pass" {
			t.Fatalf("%s browser credentials were not applied", protocol)
		}
	}
	if target := targets[config.SSH]; target.Username != "" || target.Password != "" {
		t.Fatal("SSH target must not receive browser credentials")
	}
}

func TestRuntimeDurationIncludesRampAndHold(t *testing.T) {
	if got := runtimeDuration(config.Config{Ramp: 10 * time.Minute, Hold: 30 * time.Minute}); got != 40*time.Minute {
		t.Fatalf("duration=%s", got)
	}
}

func TestDefaultStopPolicyStopsSmallCasesOnFirstFailure(t *testing.T) {
	small := defaultStopPolicy(20)
	if small.MinAttempts != 1 || small.MaxFailureRate != .01 || small.MaxDisconnectRate != .01 {
		t.Fatalf("small policy=%+v", small)
	}
	large := defaultStopPolicy(100)
	if large.MinAttempts != 100 {
		t.Fatalf("large policy=%+v", large)
	}
}

func TestEffectiveStopPolicyKeepsContinueOnErrorsRunAlive(t *testing.T) {
	policy := effectiveStopPolicy(config.Config{Total: 1000, ContinueOnErrors: true}, loadmetrics.StopPolicy{})
	if stop, reason := policy.Evaluate(loadmetrics.Snapshot{Attempts: 1000, Failures: 1000, Disconnects: 1000}); stop {
		t.Fatalf("continue-on-errors run stopped: %s", reason)
	}
}

type observationRunner struct{ observation session.Observation }

func (r observationRunner) Run(context.Context, session.Job) (session.Handle, error) {
	return observationHandle{observation: r.observation}, nil
}

type observationHandle struct{ observation session.Observation }

func (h observationHandle) Wait(context.Context) session.Observation { return h.observation }
func (observationHandle) Close() error                               { return nil }

type failedStartRunner struct{ err error }

func (r failedStartRunner) Run(context.Context, session.Job) (session.Handle, error) {
	return nil, r.err
}

func TestReportingRunnerPassesSanitizedFailureCausesToReport(t *testing.T) {
	job := config.Job{ID: 1, Protocol: config.SSH, Mode: config.Direct, AssetID: "asset", AccountID: "account"}

	startTracker, _ := runreport.NewTracker("start-failure", []config.Job{job})
	startRunner := &reportingRunner{inner: failedStartRunner{err: errors.New("PAM no_connect secret-start-detail")}, tracker: startTracker}
	if _, err := startRunner.Run(context.Background(), session.Job(job)); err == nil {
		t.Fatal("expected start failure")
	}
	if got := startTracker.Snapshot("failed").FailureReasons["start/pam_no_connect"]; got != 1 {
		t.Fatalf("start failure count=%d", got)
	}

	runtimeTracker, _ := runreport.NewTracker("runtime-failure", []config.Job{job})
	runtimeRunner := &reportingRunner{inner: observationRunner{observation: session.Observation{Reason: session.Failed, Err: errors.New("websocket inbound traffic inactive for 15s secret-runtime-detail")}}, tracker: runtimeTracker}
	handle, err := runtimeRunner.Run(context.Background(), session.Job(job))
	if err != nil {
		t.Fatal(err)
	}
	_ = handle.Wait(context.Background())
	if got := runtimeTracker.Snapshot("failed").FailureReasons["runtime/inbound_inactive"]; got != 1 {
		t.Fatalf("runtime failure count=%d", got)
	}
}

func TestReportingRunnerRecordsTerminalObservation(t *testing.T) {
	job := config.Job{ID: 1, Protocol: config.SSH, Mode: config.Direct, AssetID: "asset", AccountID: "account"}
	tracker, err := runreport.NewTracker("run", []config.Job{job})
	if err != nil {
		t.Fatal(err)
	}
	runner := &reportingRunner{inner: observationRunner{observation: session.Observation{Reason: session.Cancelled, Mode: config.Direct, ConnectLatency: 50 * time.Millisecond, SentBytes: 10, ReceivedBytes: 20, ActivityEvents: 3, LastActivity: time.Now()}}, tracker: tracker}
	handle, err := runner.Run(context.Background(), session.Job(job))
	if err != nil {
		t.Fatal(err)
	}
	_ = handle.Wait(context.Background())
	report := tracker.Snapshot("completed")
	if report.Evidence.ConnectLatencyP50Millis != 50 || report.Evidence.SentBytes != 10 || report.Evidence.ActivityEvents != 3 || report.Totals.Maintained != 1 {
		t.Fatalf("report=%+v", report)
	}
}

func TestReportingRunnerTreatsCompletedAfterCloseAsMaintained(t *testing.T) {
	job := config.Job{ID: 1, Protocol: config.SSH, Mode: config.Direct, AssetID: "asset", AccountID: "account"}
	tracker, err := runreport.NewTracker("run", []config.Job{job})
	if err != nil {
		t.Fatal(err)
	}
	runner := &reportingRunner{inner: observationRunner{observation: session.Observation{Reason: session.Completed, Mode: config.Direct, ConnectLatency: 50 * time.Millisecond, SentBytes: 10, ReceivedBytes: 20, ActivityEvents: 3, LastActivity: time.Now()}}, tracker: tracker}
	handle, err := runner.Run(context.Background(), session.Job(job))
	if err != nil {
		t.Fatal(err)
	}
	if err := handle.Close(); err != nil {
		t.Fatal(err)
	}
	_ = handle.Wait(context.Background())
	report := tracker.Snapshot("completed")
	if report.Totals.RuntimeFailures != 0 || report.Totals.Maintained != 1 {
		t.Fatalf("report=%+v", report)
	}
}

func TestReportingRunnerRejectsStaleCompletedAfterClose(t *testing.T) {
	job := config.Job{ID: 1, Protocol: config.SSH, Mode: config.Direct, AssetID: "asset", AccountID: "account"}
	tracker, err := runreport.NewTracker("run", []config.Job{job})
	if err != nil {
		t.Fatal(err)
	}
	runner := &reportingRunner{inner: observationRunner{observation: session.Observation{Reason: session.Completed, Mode: config.Direct, ConnectLatency: 50 * time.Millisecond, SentBytes: 10, ReceivedBytes: 20, ActivityEvents: 3, LastActivity: time.Now().Add(-10 * time.Second)}}, tracker: tracker}
	handle, err := runner.Run(context.Background(), session.Job(job))
	if err != nil {
		t.Fatal(err)
	}
	if err := handle.Close(); err != nil {
		t.Fatal(err)
	}
	_ = handle.Wait(context.Background())
	report := tracker.Snapshot("completed")
	if report.Totals.RuntimeFailures != 1 || report.Totals.Maintained != 0 {
		t.Fatalf("report=%+v", report)
	}
}

func TestReportingRunnerRejectsCompletedWithActivityAfterClose(t *testing.T) {
	job := config.Job{ID: 1, Protocol: config.SSH, Mode: config.Direct, AssetID: "asset", AccountID: "account"}
	tracker, err := runreport.NewTracker("run", []config.Job{job})
	if err != nil {
		t.Fatal(err)
	}
	runner := &reportingRunner{inner: observationRunner{observation: session.Observation{Reason: session.Completed, Mode: config.Direct, ConnectLatency: 50 * time.Millisecond, SentBytes: 10, ReceivedBytes: 20, ActivityEvents: 3, LastActivity: time.Now().Add(time.Hour)}}, tracker: tracker}
	handle, err := runner.Run(context.Background(), session.Job(job))
	if err != nil {
		t.Fatal(err)
	}
	if err := handle.Close(); err != nil {
		t.Fatal(err)
	}
	_ = handle.Wait(context.Background())
	report := tracker.Snapshot("completed")
	if report.Totals.RuntimeFailures != 1 || report.Totals.Maintained != 0 {
		t.Fatalf("report=%+v", report)
	}
}

func TestReportingRunnerRejectsUnconnectedOrInactiveSessionAsMaintained(t *testing.T) {
	job := config.Job{ID: 1, Protocol: config.SSH, Mode: config.Direct, AssetID: "asset", AccountID: "account"}
	for name, observation := range map[string]session.Observation{
		"unconnected": {Reason: session.Cancelled, Mode: config.Direct},
		"inactive":    {Reason: session.Cancelled, Mode: config.Direct, ConnectLatency: 10 * time.Millisecond},
		"one-way":     {Reason: session.Cancelled, Mode: config.Direct, ConnectLatency: 10 * time.Millisecond, SentBytes: 10, ActivityEvents: 1},
		"ended-early": {Reason: session.Completed, Mode: config.Direct, ConnectLatency: 10 * time.Millisecond, SentBytes: 10, ReceivedBytes: 10, ActivityEvents: 1},
	} {
		t.Run(name, func(t *testing.T) {
			tracker, _ := runreport.NewTracker("run", []config.Job{job})
			runner := &reportingRunner{inner: observationRunner{observation: observation}, tracker: tracker}
			handle, err := runner.Run(context.Background(), session.Job(job))
			if err != nil {
				t.Fatal(err)
			}
			_ = handle.Wait(context.Background())
			report := tracker.Snapshot("completed")
			if report.Totals.RuntimeFailures != 1 || report.Totals.Maintained != 0 {
				t.Fatalf("report=%+v", report)
			}
		})
	}
}

func TestTerminalEvidenceRejectsCompletedReportWithRuntimeFailure(t *testing.T) {
	report := runreport.Report{Status: "completed", Totals: runreport.Counts{Planned: 1, Used: 1, Started: 1, RuntimeFailures: 1}}
	if err := terminalEvidenceError(report); err == nil {
		t.Fatal("expected terminal evidence failure")
	}
	report.Totals.RuntimeFailures = 0
	report.Totals.Maintained = 1
	if err := terminalEvidenceError(report); err != nil {
		t.Fatal(err)
	}
}
