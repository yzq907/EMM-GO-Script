package app

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"pam-loadtest/internal/config"
	"pam-loadtest/internal/distributed"
	"pam-loadtest/internal/inventory"
	"pam-loadtest/internal/runreport"
	"pam-loadtest/internal/session"
)

type failFirstStatusOperations struct {
	distributed.AgentOperations
	calls atomic.Int32
}

func TestApplyRequestRuntimePolicy(t *testing.T) {
	cfg := config.Config{SSHActivityInterval: time.Second}
	applyRequestRuntimePolicy(&cfg, distributed.RunRequest{
		SSHActivityIntervalNanos:       int64(5 * time.Second),
		SSHActivityMode:                "keepalive",
		GraphicalActivityIntervalNanos: map[string]int64{"rdp": int64(3 * time.Second), "web": int64(5 * time.Second)},
		ContinueOnErrors:               true,
		ConnectRetries:                 3,
	})
	if cfg.SSHActivityInterval != 5*time.Second {
		t.Fatalf("SSH activity interval=%s", cfg.SSHActivityInterval)
	}
	if cfg.SSHActivityMode != "keepalive" {
		t.Fatalf("SSH activity mode=%q", cfg.SSHActivityMode)
	}
	if !cfg.ContinueOnErrors {
		t.Fatal("continue-on-errors policy was not applied")
	}
	if cfg.ConnectRetries != 3 {
		t.Fatalf("connect retries=%d", cfg.ConnectRetries)
	}
	if got := cfg.ActivityInterval(config.RDP); got != 3*time.Second {
		t.Fatalf("RDP activity interval=%s", got)
	}
	if got := cfg.ActivityInterval(config.Web); got != 5*time.Second {
		t.Fatalf("WEB activity interval=%s", got)
	}
}

func TestApplyRequestRuntimePolicyCarriesConnectionOnly(t *testing.T) {
	cfg := config.Config{}
	applyRequestRuntimePolicy(&cfg, distributed.RunRequest{ConnectionOnly: true})
	if !cfg.ConnectionOnly {
		t.Fatal("connection-only policy was not propagated")
	}
}

func (o *failFirstStatusOperations) Status(ctx context.Context, request distributed.StatusRequest) (distributed.StatusResponse, error) {
	if o.calls.Add(1) == 1 {
		return distributed.StatusResponse{}, errors.New("transient status failure")
	}
	return o.AgentOperations.Status(ctx, request)
}

func startFailingControllerTestAgent(t *testing.T, token string) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	capabilities := distributed.Capabilities{Version: BuildVersion, Capacity: 1, DirectCapacity: 1, BrowserCapacity: 1, DirectProtocols: []string{"ssh", "rdp", "vnc", "web", "mysql"}}
	registry := distributed.NewRegistryWithCapabilities(capabilities, func(_ context.Context, request distributed.RunRequest) (runreport.Report, error) {
		wire := request.Jobs[0]
		job := config.Job{ID: wire.ID, Protocol: config.Protocol(wire.Protocol), Mode: config.ExecutionMode(wire.Mode), AssetID: wire.AssetID, AccountID: wire.AccountID}
		tracker, trackerErr := runreport.NewTrackerWithBuildVersion(request.RunID, BuildVersion, []config.Job{job})
		if trackerErr != nil {
			return runreport.Report{}, trackerErr
		}
		tracker.Attempt(job)
		tracker.Started(job)
		tracker.Record(job, session.Observation{ConnectLatency: time.Millisecond, ActivityEvents: 1, LastActivity: time.Now()})
		tracker.RuntimeFailed(job)
		return tracker.Snapshot("failed"), errors.New("secret runtime detail")
	})
	server := distributed.NewAgentServerWithCapabilities(token, capabilities, registry)
	go server.Serve(listener)
	t.Cleanup(func() { server.Stop(); _ = listener.Close() })
	return listener.Addr().String()
}

func startControllerTestAgent(t *testing.T, token string, received chan<- distributed.RunRequest) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	capabilities := distributed.Capabilities{Version: BuildVersion, Capacity: 1, DirectCapacity: 1, BrowserCapacity: 1, DirectProtocols: []string{"ssh", "rdp", "vnc", "web", "mysql"}}
	registry := distributed.NewRegistryWithCapabilities(capabilities, func(_ context.Context, request distributed.RunRequest) (runreport.Report, error) {
		received <- request
		jobs := make([]config.Job, len(request.Jobs))
		for i, job := range request.Jobs {
			jobs[i] = config.Job{ID: job.ID, Protocol: config.Protocol(job.Protocol), Mode: config.ExecutionMode(job.Mode), AssetID: job.AssetID, AccountID: job.AccountID}
		}
		tracker, err := runreport.NewTracker(request.RunID, jobs)
		if err != nil {
			return runreport.Report{}, err
		}
		for _, job := range jobs {
			tracker.Attempt(job)
			tracker.Started(job)
			tracker.Record(job, session.Observation{ConnectLatency: time.Millisecond, SentBytes: 1, ReceivedBytes: 1, ActivityEvents: 1, LastActivity: time.Now()})
			tracker.Maintained(job)
		}
		return tracker.Snapshot("completed"), nil
	})
	server := distributed.NewAgentServerWithCapabilities(token, capabilities, registry)
	go server.Serve(listener)
	t.Cleanup(func() { server.Stop(); _ = listener.Close() })
	return listener.Addr().String()
}

func startTimestampControllerTestAgent(t *testing.T, token string, received chan<- time.Time) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	capabilities := distributed.Capabilities{Version: BuildVersion, Capacity: 1, DirectCapacity: 1, BrowserCapacity: 1, DirectProtocols: []string{"ssh", "rdp", "vnc", "web", "mysql"}}
	registry := distributed.NewRegistryWithCapabilities(capabilities, func(_ context.Context, request distributed.RunRequest) (runreport.Report, error) {
		received <- time.Now()
		wire := request.Jobs[0]
		job := config.Job{ID: wire.ID, Protocol: config.Protocol(wire.Protocol), Mode: config.ExecutionMode(wire.Mode), AssetID: wire.AssetID, AccountID: wire.AccountID}
		tracker, err := runreport.NewTracker(request.RunID, []config.Job{job})
		if err != nil {
			return runreport.Report{}, err
		}
		tracker.Attempt(job)
		tracker.Started(job)
		tracker.Record(job, session.Observation{ConnectLatency: time.Millisecond, SentBytes: 1, ReceivedBytes: 1, ActivityEvents: 1, LastActivity: time.Now()})
		tracker.Maintained(job)
		return tracker.Snapshot("completed"), nil
	})
	server := distributed.NewAgentServerWithCapabilities(token, capabilities, registry)
	go server.Serve(listener)
	t.Cleanup(func() { server.Stop(); _ = listener.Close() })
	return listener.Addr().String()
}

func startCancellableControllerTestAgent(t *testing.T, token string, failFirstStatus bool, started, cancelled chan<- struct{}) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	capabilities := distributed.Capabilities{Version: BuildVersion, Capacity: 1, DirectCapacity: 1, BrowserCapacity: 1, DirectProtocols: []string{"ssh", "rdp", "vnc", "web", "mysql"}}
	registry := distributed.NewRegistryWithCapabilities(capabilities, func(ctx context.Context, request distributed.RunRequest) (runreport.Report, error) {
		wire := request.Jobs[0]
		job := config.Job{ID: wire.ID, Protocol: config.Protocol(wire.Protocol), Mode: config.ExecutionMode(wire.Mode), AssetID: wire.AssetID, AccountID: wire.AccountID}
		tracker, trackerErr := runreport.NewTrackerWithBuildVersion(request.RunID, BuildVersion, []config.Job{job})
		if trackerErr != nil {
			return runreport.Report{}, trackerErr
		}
		tracker.Attempt(job)
		tracker.Started(job)
		tracker.Record(job, session.Observation{ConnectLatency: time.Millisecond, SentBytes: 1, ReceivedBytes: 1, ActivityEvents: 1, LastActivity: time.Now()})
		tracker.Maintained(job)
		started <- struct{}{}
		<-ctx.Done()
		cancelled <- struct{}{}
		return tracker.Snapshot("cancelled"), ctx.Err()
	})
	var operations distributed.AgentOperations = registry
	if failFirstStatus {
		operations = &failFirstStatusOperations{AgentOperations: registry}
	}
	server := distributed.NewAgentServerWithCapabilities(token, capabilities, operations)
	go server.Serve(listener)
	t.Cleanup(func() { server.Stop(); _ = listener.Close() })
	return listener.Addr().String()
}

func TestRunControllerGloballyBindsWaitsAndAggregates(t *testing.T) {
	dir := t.TempDir()
	scenario := filepath.Join(dir, "scenario.yaml")
	if err := os.WriteFile(scenario, []byte(`name: controller-test
total: 2
ramp: 1ms
hold: 1ms
ssh_activity_interval: 5s
ssh_activity_mode: keepalive
graphical_activity_intervals: {rdp: 3s}
continue_on_errors: true
connect_retries: 3
seed: 42
protocols: {ssh: 2}
pam: {base_url: http://pam.test, username_env: PAM_USERNAME, password_env: PAM_PASSWORD}
assets: {ssh: {asset_id_env: SSH_ASSET_ID, account_id_env: SSH_ACCOUNT_ID}}
`), 0600); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(dir, "manifest.json")
	manifest := inventory.Manifest{Version: 1, Assets: []inventory.ManifestAsset{
		{Name: "one", IP: "10.1.0.1", Protocol: "ssh", AssetID: "asset-1", AccountID: "account-1"},
		{Name: "two", IP: "10.1.0.2", Protocol: "ssh", AssetID: "asset-2", AccountID: "account-2"},
	}}
	if err := inventory.WriteManifest(manifestPath, manifest); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PAM_ASSET_MANIFEST", manifestPath)
	t.Setenv("PAM_CONTROLLER_GRACE", "1s")
	received := make(chan distributed.RunRequest, 2)
	token := "runtime-controller-token"
	addresses := []string{startControllerTestAgent(t, token, received), startControllerTestAgent(t, token, received)}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	report, err := RunController(ctx, scenario, addresses, token)
	if err != nil {
		t.Fatal(err)
	}
	if report.Totals.Planned != 2 || report.Totals.Used != 2 || report.Totals.Duplicates != 0 || report.Totals.Unused != 0 {
		t.Fatalf("report=%+v", report)
	}
	one, two := <-received, <-received
	if one.Jobs[0].AssetID == "" || one.Jobs[0].AssetID == two.Jobs[0].AssetID {
		t.Fatalf("requests=%+v %+v", one, two)
	}
	for _, request := range []distributed.RunRequest{one, two} {
		if request.SSHActivityIntervalNanos != int64(5*time.Second) {
			t.Fatalf("SSH activity interval=%s", time.Duration(request.SSHActivityIntervalNanos))
		}
		if request.SSHActivityMode != "keepalive" {
			t.Fatalf("SSH activity mode=%q", request.SSHActivityMode)
		}
		if got := time.Duration(request.GraphicalActivityIntervalNanos["rdp"]); got != 3*time.Second {
			t.Fatalf("RDP activity interval=%s", got)
		}
		if !request.ContinueOnErrors {
			t.Fatal("continue-on-errors policy was not propagated")
		}
		if request.ConnectRetries != 3 {
			t.Fatalf("connect retries=%d", request.ConnectRetries)
		}
	}
}

func TestRunControllerCanShareAuthenticatedPAMTokenWithAgents(t *testing.T) {
	scenario, manifestPath := writeTwoJobControllerFixture(t, "controller-shared-token")
	t.Setenv("PAM_ASSET_MANIFEST", manifestPath)
	t.Setenv("PAM_CONTROLLER_GRACE", "1s")
	t.Setenv("PAM_SHARE_LOGIN_TOKEN", "true")
	t.Setenv("PAM_USERNAME", "user")
	t.Setenv("PAM_PASSWORD", "pass")

	pamServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			w.Header().Set("X-Auth-Token", "shared-runtime-token")
			_ = json.NewEncoder(w).Encode(map[string]string{"token": "shared-runtime-token"})
		case "/login/crypto-key":
			http.NotFound(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
	defer pamServer.Close()
	replaceScenarioPAMBaseURL(t, scenario, pamServer.URL)

	received := make(chan distributed.RunRequest, 2)
	token := "runtime-controller-token"
	addresses := []string{startControllerTestAgent(t, token, received), startControllerTestAgent(t, token, received)}
	if _, err := RunController(context.Background(), scenario, addresses, token); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		request := <-received
		if request.PAMToken != "shared-runtime-token" {
			t.Fatalf("request PAM token=%q", request.PAMToken)
		}
	}
}

func TestRunControllerCanShareAuthenticatedPAMCookiesWithAgents(t *testing.T) {
	scenario, manifestPath := writeTwoJobControllerFixture(t, "controller-shared-cookies")
	t.Setenv("PAM_ASSET_MANIFEST", manifestPath)
	t.Setenv("PAM_CONTROLLER_GRACE", "1s")
	t.Setenv("PAM_SHARE_LOGIN_TOKEN", "true")
	t.Setenv("PAM_USERNAME", "user")
	t.Setenv("PAM_PASSWORD", "pass")

	pamServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: "shared-cookie", Path: "/"})
			_ = json.NewEncoder(w).Encode(map[string]any{"code": 1, "data": map[string]any{"info": map[string]string{"username": "user"}}})
		case "/login/crypto-key":
			http.NotFound(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
	defer pamServer.Close()
	replaceScenarioPAMBaseURL(t, scenario, pamServer.URL)

	received := make(chan distributed.RunRequest, 2)
	token := "runtime-controller-token"
	addresses := []string{startControllerTestAgent(t, token, received), startControllerTestAgent(t, token, received)}
	if _, err := RunController(context.Background(), scenario, addresses, token); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		request := <-received
		if len(request.PAMCookies) != 1 || request.PAMCookies[0].Name != "sid" || request.PAMCookies[0].Value != "shared-cookie" {
			t.Fatalf("request PAM cookies=%+v", request.PAMCookies)
		}
	}
}

func replaceScenarioPAMBaseURL(t *testing.T, path, baseURL string) {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	updated := strings.ReplaceAll(string(body), "http://pam.test", baseURL)
	if err := os.WriteFile(path, []byte(updated), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestRunControllerCanStaggerAgentStarts(t *testing.T) {
	scenario, manifestPath := writeTwoJobControllerFixture(t, "controller-stagger")
	t.Setenv("PAM_ASSET_MANIFEST", manifestPath)
	t.Setenv("PAM_CONTROLLER_GRACE", "1s")
	t.Setenv("PAM_AGENT_START_DELAY", "50ms")
	token := "runtime-controller-token"
	received := make(chan time.Time, 2)
	addresses := []string{
		startTimestampControllerTestAgent(t, token, received),
		startTimestampControllerTestAgent(t, token, received),
	}

	if _, err := RunController(context.Background(), scenario, addresses, token); err != nil {
		t.Fatal(err)
	}
	first, second := <-received, <-received
	if delta := second.Sub(first); delta < 45*time.Millisecond {
		t.Fatalf("agent starts were not staggered: delta=%s", delta)
	}
}

func TestRunControllerRequiresManifestBeforeDialing(t *testing.T) {
	t.Setenv("PAM_ASSET_MANIFEST", "")
	if _, err := RunController(context.Background(), "missing.yaml", []string{"127.0.0.1:1"}, "token"); err == nil {
		t.Fatal("expected manifest requirement")
	}
}

func TestRunControllerReturnsGlobalTerminalReportWhenAnAgentFails(t *testing.T) {
	dir := t.TempDir()
	scenario := filepath.Join(dir, "scenario.yaml")
	if err := os.WriteFile(scenario, []byte(`name: controller-failure
total: 2
ramp: 1ms
hold: 1ms
seed: 42
protocols: {ssh: 2}
pam: {base_url: http://pam.test, username_env: PAM_USERNAME, password_env: PAM_PASSWORD}
assets: {ssh: {asset_id_env: SSH_ASSET_ID, account_id_env: SSH_ACCOUNT_ID}}
`), 0600); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(dir, "manifest.json")
	manifest := inventory.Manifest{Version: 1, Assets: []inventory.ManifestAsset{
		{Name: "one", IP: "10.1.0.1", Protocol: "ssh", AssetID: "asset-1", AccountID: "account-1"},
		{Name: "two", IP: "10.1.0.2", Protocol: "ssh", AssetID: "asset-2", AccountID: "account-2"},
	}}
	if err := inventory.WriteManifest(manifestPath, manifest); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PAM_ASSET_MANIFEST", manifestPath)
	t.Setenv("PAM_CONTROLLER_GRACE", "1s")
	token := "runtime-controller-token"
	received := make(chan distributed.RunRequest, 1)
	addresses := []string{startFailingControllerTestAgent(t, token), startControllerTestAgent(t, token, received)}
	report, err := RunController(context.Background(), scenario, addresses, token)
	if err == nil {
		t.Fatal("expected failed distributed run")
	}
	if report.Status != "failed" || report.Totals.Planned != 2 || report.Totals.RuntimeFailures != 1 || report.Totals.Maintained != 1 || len(report.Agents) != 2 {
		t.Fatalf("report=%+v err=%v", report, err)
	}
}

func TestRunControllerCancelsOtherAgentsAndCollectsReportsAfterAgentFailure(t *testing.T) {
	scenario, manifestPath := writeTwoJobControllerFixture(t, "controller-agent-failure")
	t.Setenv("PAM_ASSET_MANIFEST", manifestPath)
	t.Setenv("PAM_CONTROLLER_GRACE", "1s")
	token := "runtime-controller-token"
	started := make(chan struct{}, 1)
	cancelled := make(chan struct{}, 1)
	addresses := []string{
		startFailingControllerTestAgent(t, token),
		startCancellableControllerTestAgent(t, token, false, started, cancelled),
	}

	report, err := RunController(context.Background(), scenario, addresses, token)
	if err == nil {
		t.Fatal("expected failed distributed run")
	}
	if report.Status != "failed" || report.Totals.Planned != 2 || len(report.Agents) != 2 {
		t.Fatalf("report=%+v err=%v", report, err)
	}
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("running agent was not cancelled after peer failure")
	}
}

func TestRunControllerCollectsCancelledReportsAfterStatusError(t *testing.T) {
	scenario, manifestPath := writeTwoJobControllerFixture(t, "controller-status-error")
	t.Setenv("PAM_ASSET_MANIFEST", manifestPath)
	t.Setenv("PAM_CONTROLLER_GRACE", "1s")
	token := "runtime-controller-token"
	started := make(chan struct{}, 2)
	cancelled := make(chan struct{}, 2)
	addresses := []string{
		startCancellableControllerTestAgent(t, token, true, started, cancelled),
		startCancellableControllerTestAgent(t, token, false, started, cancelled),
	}

	report, err := RunController(context.Background(), scenario, addresses, token)
	if err == nil {
		t.Fatal("expected controller status failure")
	}
	if report.Status != "failed" || report.Totals.Planned != 2 || len(report.Agents) != 2 {
		t.Fatalf("report=%+v err=%v", report, err)
	}
}

func TestRunControllerUsesIndependentCleanupContextAfterParentCancellation(t *testing.T) {
	scenario, manifestPath := writeTwoJobControllerFixture(t, "controller-parent-cancel")
	t.Setenv("PAM_ASSET_MANIFEST", manifestPath)
	t.Setenv("PAM_CONTROLLER_GRACE", "1s")
	token := "runtime-controller-token"
	started := make(chan struct{}, 2)
	cancelled := make(chan struct{}, 2)
	addresses := []string{
		startCancellableControllerTestAgent(t, token, false, started, cancelled),
		startCancellableControllerTestAgent(t, token, false, started, cancelled),
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-started
		<-started
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	report, err := RunController(ctx, scenario, addresses, token)
	if err == nil {
		t.Fatal("expected controller cancellation")
	}
	if report.Status != "cancelled" || report.Totals.Planned != 2 || len(report.Agents) != 2 {
		t.Fatalf("report=%+v err=%v", report, err)
	}
}

func writeTwoJobControllerFixture(t *testing.T, name string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	scenario := filepath.Join(dir, "scenario.yaml")
	body := []byte("name: " + name + `
total: 2
ramp: 1ms
hold: 1ms
seed: 42
protocols: {ssh: 2}
pam: {base_url: http://pam.test, username_env: PAM_USERNAME, password_env: PAM_PASSWORD}
assets: {ssh: {asset_id_env: SSH_ASSET_ID, account_id_env: SSH_ACCOUNT_ID}}
`)
	if err := os.WriteFile(scenario, body, 0600); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(dir, "manifest.json")
	manifest := inventory.Manifest{Version: 1, Assets: []inventory.ManifestAsset{
		{Name: "one", IP: "10.1.0.1", Protocol: "ssh", AssetID: "asset-1", AccountID: "account-1"},
		{Name: "two", IP: "10.1.0.2", Protocol: "ssh", AssetID: "asset-2", AccountID: "account-2"},
	}}
	if err := inventory.WriteManifest(manifestPath, manifest); err != nil {
		t.Fatal(err)
	}
	return scenario, manifestPath
}
