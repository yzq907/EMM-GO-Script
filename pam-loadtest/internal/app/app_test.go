package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"pam-loadtest/internal/config"
	"pam-loadtest/internal/distributed"
	"pam-loadtest/internal/inventory"
	"pam-loadtest/internal/runreport"
)

func TestWriteRunReportContainsCountsOnly(t *testing.T) {
	report := runreport.Report{RunID: "run-1", Status: "completed", Totals: runreport.Counts{Planned: 2, Used: 2}, Protocols: map[config.Protocol]runreport.Counts{config.SSH: {Planned: 2, Used: 2}}}
	var out bytes.Buffer
	if err := writeRunReport(&out, report); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, expected := range []string{"\"planned\":2", "\"used\":2", "\"ssh\""} {
		if !strings.Contains(text, expected) {
			t.Fatalf("output=%q", text)
		}
	}
	for _, forbidden := range []string{"asset_id", "account_id", "password", "cookie", "token"} {
		if strings.Contains(strings.ToLower(text), forbidden) {
			t.Fatalf("report contains %q: %s", forbidden, text)
		}
	}
}

func TestFinishControllerRunWritesFailedTerminalReport(t *testing.T) {
	report := runreport.Report{Version: 1, RunID: "failed-run", Status: "failed", Totals: runreport.Counts{Planned: 2, RuntimeFailures: 1, Maintained: 1}}
	var out, errOut bytes.Buffer
	if code := finishControllerRun(&out, &errOut, report, errors.New("distributed run failed")); code != 1 {
		t.Fatalf("code=%d", code)
	}
	if !strings.Contains(out.String(), `"status":"failed"`) || !strings.Contains(out.String(), `"runtime_failures":1`) {
		t.Fatalf("report output=%q", out.String())
	}
	if !strings.Contains(errOut.String(), "controller failed") {
		t.Fatalf("error output=%q", errOut.String())
	}
}

func TestValidateCommandPrintsOnlyScenarioMetadata(t *testing.T) {
	p := filepath.Join(t.TempDir(), "scenario.yaml")
	body := `name: smoke
total: 1
ramp: 1m
hold: 1m
protocols: {ssh: 1}
pam: {base_url: http://pam.test, username_env: PAM_USERNAME, password_env: PAM_PASSWORD}
`
	if err := os.WriteFile(p, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	code := Run([]string{"validate", p}, &out, &errOut)
	if code != 0 || !strings.Contains(out.String(), "smoke") || strings.Contains(out.String(), "PAM_PASSWORD") {
		t.Fatalf("code=%d out=%q err=%q", code, out.String(), errOut.String())
	}
}

func TestValidateCommandRejectsUnknownCommand(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := Run([]string{"destroy"}, &out, &errOut); code != 2 {
		t.Fatalf("code=%d", code)
	}
}

func TestRunCommandRequiresScenarioPath(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := Run([]string{"run"}, &out, &errOut); code != 2 || !strings.Contains(errOut.String(), "run <scenario.yaml>") {
		t.Fatalf("code=%d err=%q", code, errOut.String())
	}
}

func TestAgentCommandRequiresRuntimeToken(t *testing.T) {
	t.Setenv("PAM_AGENT_TOKEN", "")
	var out, errOut bytes.Buffer
	code := Run([]string{"agent", "scenario.yaml"}, &out, &errOut)
	if code != 1 || !strings.Contains(errOut.String(), "PAM_AGENT_TOKEN") {
		t.Fatalf("code=%d err=%q", code, errOut.String())
	}
}

func TestAgentDirectCapacityEnvironmentIsIndependent(t *testing.T) {
	t.Setenv("PAM_AGENT_DIRECT_CAPACITY", "242")
	capacity, err := agentDirectCapacity(250)
	if err != nil || capacity != 242 {
		t.Fatalf("capacity=%d err=%v", capacity, err)
	}
	t.Setenv("PAM_AGENT_DIRECT_CAPACITY", "invalid")
	if _, err := agentDirectCapacity(250); err == nil {
		t.Fatal("expected invalid direct capacity rejection")
	}
}

func TestControllerCommandRequiresAgentList(t *testing.T) {
	t.Setenv("PAM_AGENTS", "")
	var out, errOut bytes.Buffer
	code := Run([]string{"controller", "scenario.yaml"}, &out, &errOut)
	if code != 1 || !strings.Contains(errOut.String(), "PAM_AGENTS") {
		t.Fatalf("code=%d err=%q", code, errOut.String())
	}
}

func TestAgentHealthCommandRequiresRuntimeToken(t *testing.T) {
	t.Setenv("PAM_AGENT_TOKEN", "")
	var out, errOut bytes.Buffer
	code := Run([]string{"agent-health", "127.0.0.1:9443"}, &out, &errOut)
	if code != 1 || !strings.Contains(errOut.String(), "PAM_AGENT_TOKEN") {
		t.Fatalf("code=%d out=%q err=%q", code, out.String(), errOut.String())
	}
}

func TestAgentHealthCommandPrintsCapabilityJSON(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	capabilities := distributed.Capabilities{Version: "build-123", Capacity: 250, DirectCapacity: 247, BrowserCapacity: 3, DirectProtocols: []string{"ssh", "rdp", "vnc", "web", "mysql"}}
	registry := distributed.NewRegistryWithCapabilities(capabilities, func(context.Context, distributed.RunRequest) (runreport.Report, error) {
		return runreport.Report{}, nil
	})
	server := distributed.NewAgentServerWithCapabilities("health-token", capabilities, registry)
	go server.Serve(listener)
	defer server.Stop()
	t.Setenv("PAM_AGENT_TOKEN", "health-token")
	var out, errOut bytes.Buffer
	code := Run([]string{"agent-health", listener.Addr().String()}, &out, &errOut)
	if code != 0 {
		t.Fatalf("code=%d out=%q err=%q", code, out.String(), errOut.String())
	}
	var health distributed.HealthResponse
	if err := json.Unmarshal(out.Bytes(), &health); err != nil || health.Capabilities.Version != "build-123" || health.Capabilities.BrowserCapacity != 3 {
		t.Fatalf("health=%+v err=%v", health, err)
	}
}

func TestInventoryPlanCommandWritesNonSensitiveDefaultInventory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inventory.json")
	var out, errOut bytes.Buffer
	code := Run([]string{"inventory", "plan", path}, &out, &errOut)
	if code != 0 {
		t.Fatalf("code=%d err=%q", code, errOut.String())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var assets []inventory.Asset
	if err := json.Unmarshal(raw, &assets); err != nil {
		t.Fatal(err)
	}
	if len(assets) != 2000 {
		t.Fatalf("asset count = %d, want 2000", len(assets))
	}
	if strings.Contains(strings.ToLower(string(raw)), "password") {
		t.Fatal("inventory plan contains a password field")
	}
	if !strings.Contains(out.String(), "2000") {
		t.Fatalf("output = %q", out.String())
	}
}

func TestInventoryPlanCommandSupportsExtensionCombinedAndCapacityProfiles(t *testing.T) {
	for profile, want := range map[string]int{"extension": 150, "combined": 2150, "capacity": 4150} {
		t.Run(profile, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), profile+".json")
			var out, errOut bytes.Buffer
			code := Run([]string{"inventory", "plan", "--profile=" + profile, path}, &out, &errOut)
			if code != 0 {
				t.Fatalf("code=%d err=%q", code, errOut.String())
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var assets []inventory.Asset
			if err := json.Unmarshal(raw, &assets); err != nil || len(assets) != want {
				t.Fatalf("count=%d err=%v", len(assets), err)
			}
		})
	}
}

func TestInventoryApplyDefaultsToDryRun(t *testing.T) {
	imports := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			json.NewEncoder(w).Encode(map[string]any{"code": 1, "data": map[string]string{"token": "runtime-token"}})
		case "/assets/paging":
			json.NewEncoder(w).Encode(map[string]any{"code": 1, "data": map[string]any{"items": []any{}, "total": 0}})
		case "/assets/import":
			imports++
			json.NewEncoder(w).Encode(map[string]any{"code": 1})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	planPath := filepath.Join(t.TempDir(), "plan.json")
	plan := []inventory.Asset{{Name: inventory.GeneratedPrefix + "one", Marker: inventory.GeneratedMarker, IP: "10.200.0.1", Protocol: "ssh", Port: 22}}
	raw, _ := json.Marshal(plan)
	if err := os.WriteFile(planPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PAM_BASE_URL", server.URL)
	t.Setenv("PAM_USERNAME", "operator")
	t.Setenv("PAM_PASSWORD", "runtime-secret")
	var out, errOut bytes.Buffer
	code := Run([]string{"inventory", "apply", planPath}, &out, &errOut)
	if code != 0 || imports != 0 || !strings.Contains(out.String(), "dry-run") {
		t.Fatalf("code=%d imports=%d out=%q err=%q", code, imports, out.String(), errOut.String())
	}
}

func TestInventoryVerifyWritesManifestForExactPlan(t *testing.T) {
	remote := inventory.RemoteAsset{ID: "asset-one", Name: inventory.GeneratedPrefix + "one", Description: inventory.GeneratedMarker, IP: "10.200.0.1", Protocol: "ssh", Port: 22, AccountCount: 1, DefaultAccountID: "account-one"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			json.NewEncoder(w).Encode(map[string]any{"code": 1, "data": map[string]string{"token": "runtime-token"}})
		case "/assets/paging":
			json.NewEncoder(w).Encode(map[string]any{"code": 1, "data": map[string]any{"items": []inventory.RemoteAsset{remote}, "total": 1}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	dir := t.TempDir()
	planPath, manifestPath := filepath.Join(dir, "plan.json"), filepath.Join(dir, "manifest.json")
	plan := []inventory.Asset{{Name: remote.Name, Marker: remote.Description, IP: remote.IP, Protocol: remote.Protocol, Port: remote.Port}}
	raw, _ := json.Marshal(plan)
	if err := os.WriteFile(planPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PAM_BASE_URL", server.URL)
	t.Setenv("PAM_USERNAME", "operator")
	t.Setenv("PAM_PASSWORD", "runtime-secret")
	var out, errOut bytes.Buffer
	code := Run([]string{"inventory", "verify", planPath, manifestPath}, &out, &errOut)
	if code != 0 {
		t.Fatalf("code=%d out=%q err=%q", code, out.String(), errOut.String())
	}
	if _, err := os.Stat(manifestPath); err != nil {
		t.Fatal(err)
	}
}
