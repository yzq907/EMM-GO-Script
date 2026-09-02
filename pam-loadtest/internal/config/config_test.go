package config

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "scenario.yaml")
	if err := os.WriteFile(p, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadExpandsApprovedMix(t *testing.T) {
	p := writeConfig(t, `name: mixed
total: 1000
ramp: 10m
hold: 30m
seed: 42
protocols:
  ssh: 600
  rdp: 100
  vnc: 100
  web: 100
  mysql: 100
pam:
  base_url: http://127.0.0.1:8088
  username_env: PAM_USERNAME
  password_env: PAM_PASSWORD
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	jobs, err := cfg.Expand()
	if err != nil {
		t.Fatal(err)
	}
	got := map[Protocol]int{}
	for _, job := range jobs {
		got[job.Protocol]++
	}
	want := map[Protocol]int{SSH: 600, RDP: 100, VNC: 100, Web: 100, MySQL: 100}
	for protocol, count := range want {
		if got[protocol] != count {
			t.Fatalf("%s: got %d want %d", protocol, got[protocol], count)
		}
	}
}

func TestLoadSSHActivityInterval(t *testing.T) {
	for _, tc := range []struct {
		name, value string
		want        time.Duration
		wantErr     bool
	}{
		{name: "default", want: time.Second},
		{name: "five seconds", value: "ssh_activity_interval: 5s\n", want: 5 * time.Second},
		{name: "subsecond", value: "ssh_activity_interval: 500ms\n", wantErr: true},
		{name: "zero", value: "ssh_activity_interval: 0s\n", wantErr: true},
		{name: "too large", value: "ssh_activity_interval: 61s\n", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := writeConfig(t, fmt.Sprintf(`name: ssh
total: 1
ramp: 1m
hold: 1m
%sprotocols: {ssh: 1}
pam: {base_url: http://127.0.0.1, username_env: PAM_USERNAME, password_env: PAM_PASSWORD}
`, tc.value))
			cfg, err := Load(p)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if cfg.SSHActivityInterval != tc.want {
				t.Fatalf("got %s want %s", cfg.SSHActivityInterval, tc.want)
			}
		})
	}
}

func TestLoadSSHActivityMode(t *testing.T) {
	for _, tc := range []struct {
		name, value, want string
		wantErr           bool
	}{
		{name: "default", want: "output"},
		{name: "keepalive", value: "ssh_activity_mode: keepalive\n", want: "keepalive"},
		{name: "invalid", value: "ssh_activity_mode: unknown\n", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := writeConfig(t, fmt.Sprintf(`name: ssh
total: 1
ramp: 1m
hold: 1m
%sprotocols: {ssh: 1}
pam: {base_url: http://127.0.0.1, username_env: PAM_USERNAME, password_env: PAM_PASSWORD}
`, tc.value))
			cfg, err := Load(p)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil || cfg.SSHActivityMode != tc.want {
				t.Fatalf("mode=%q err=%v", cfg.SSHActivityMode, err)
			}
		})
	}
}

func TestLoadGraphicalActivityIntervals(t *testing.T) {
	p := writeConfig(t, `name: mixed
total: 4
ramp: 1m
hold: 1m
graphical_activity_intervals: {rdp: 3s, vnc: 3s, web: 5s, mysql: 5s}
protocols: {rdp: 1, vnc: 1, web: 1, mysql: 1}
pam: {base_url: http://127.0.0.1, username_env: PAM_USERNAME, password_env: PAM_PASSWORD}
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	for protocol, want := range map[Protocol]time.Duration{RDP: 3 * time.Second, VNC: 3 * time.Second, Web: 5 * time.Second, MySQL: 5 * time.Second} {
		if got := cfg.ActivityInterval(protocol); got != want {
			t.Fatalf("%s=%s want %s", protocol, got, want)
		}
	}
}

func TestLoadContinueOnErrors(t *testing.T) {
	p := writeConfig(t, `name: ssh-no-early-stop
total: 1
ramp: 1m
hold: 1m
continue_on_errors: true
protocols: {ssh: 1}
pam: {base_url: http://127.0.0.1, username_env: PAM_USERNAME, password_env: PAM_PASSWORD}
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.ContinueOnErrors {
		t.Fatal("continue_on_errors was not loaded")
	}
}

func TestLoadConnectionOnly(t *testing.T) {
	p := writeConfig(t, `name: idle
total: 1
ramp: 1m
hold: 1m
connection_only: true
protocols: {ssh: 1}
pam: {base_url: http://127.0.0.1, username_env: PAM_USERNAME, password_env: PAM_PASSWORD}
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.ConnectionOnly {
		t.Fatal("connection_only was not loaded")
	}
}

func TestLoadConnectRetries(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  int
		bad   bool
	}{
		{value: "", want: 0}, {value: "connect_retries: 3\n", want: 3},
		{value: "connect_retries: 4\n", bad: true}, {value: "connect_retries: -1\n", bad: true},
	} {
		p := writeConfig(t, fmt.Sprintf(`name: retry
total: 1
ramp: 1m
hold: 1m
%sprotocols: {ssh: 1}
pam: {base_url: http://127.0.0.1, username_env: PAM_USERNAME, password_env: PAM_PASSWORD}
`, tc.value))
		cfg, err := Load(p)
		if tc.bad {
			if err == nil {
				t.Fatalf("value %q accepted", tc.value)
			}
			continue
		}
		if err != nil || cfg.ConnectRetries != tc.want {
			t.Fatalf("value %q cfg=%+v err=%v", tc.value, cfg, err)
		}
	}
}

func TestLoadRejectsInlineSecrets(t *testing.T) {
	p := writeConfig(t, `name: unsafe
total: 1
ramp: 1m
hold: 1m
protocols: {ssh: 1}
pam:
  base_url: http://127.0.0.1
  username: admin
  password: secret
`)
	if _, err := Load(p); err == nil {
		t.Fatal("expected inline credentials to be rejected")
	}
}

func TestExpandRejectsWrongTotal(t *testing.T) {
	p := writeConfig(t, `name: wrong
total: 1000
ramp: 1m
hold: 1m
protocols: {ssh: 999}
pam:
  base_url: http://127.0.0.1
  username_env: PAM_USERNAME
  password_env: PAM_PASSWORD
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cfg.Expand(); err == nil {
		t.Fatal("expected total mismatch")
	}
}

func TestExpandAssignsExplicitExecutionModes(t *testing.T) {
	p := writeConfig(t, `name: hybrid
total: 4
ramp: 1m
hold: 1m
protocols: {rdp: 3, mysql: 1}
execution_modes:
  rdp: {browser: 1, direct: 2}
  mysql: {browser: 0, direct: 1}
pam: {base_url: http://127.0.0.1, username_env: PAM_USERNAME, password_env: PAM_PASSWORD}
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	jobs, err := cfg.Expand()
	if err != nil {
		t.Fatal(err)
	}
	got := map[Protocol]map[ExecutionMode]int{}
	for _, job := range jobs {
		if got[job.Protocol] == nil {
			got[job.Protocol] = map[ExecutionMode]int{}
		}
		got[job.Protocol][job.Mode]++
	}
	if got[RDP][Browser] != 1 || got[RDP][Direct] != 2 || got[MySQL][Direct] != 1 {
		t.Fatalf("mode distribution=%v", got)
	}
}

func TestExpandRejectsExecutionModeDrift(t *testing.T) {
	cfg := Config{
		Total:          2,
		Protocols:      map[Protocol]int{RDP: 2},
		ExecutionModes: map[Protocol]ModeCounts{RDP: {Browser: 1, Direct: 2}},
	}
	if _, err := cfg.Expand(); err == nil {
		t.Fatal("expected execution mode total mismatch")
	}
}

func TestApprovedScenarioFiles(t *testing.T) {
	want := map[string]map[Protocol]int{
		"ssh-1000.yaml":      {SSH: 1000},
		"graphics-1000.yaml": {RDP: 500, VNC: 150, Web: 250, MySQL: 100},
		"mixed-1000.yaml":    {SSH: 600, RDP: 200, VNC: 50, Web: 100, MySQL: 50},
	}
	for name, counts := range want {
		t.Run(name, func(t *testing.T) {
			cfg, err := Load(filepath.Join("..", "..", "configs", name))
			if err != nil {
				t.Fatal(err)
			}
			jobs, err := cfg.Expand()
			if err != nil {
				t.Fatal(err)
			}
			got := map[Protocol]int{}
			for _, j := range jobs {
				got[j.Protocol]++
			}
			for p, count := range counts {
				if got[p] != count {
					t.Fatalf("%s=%d want %d", p, got[p], count)
				}
				mapping := cfg.Assets[p]
				if mapping.AssetIDEnv == "" || mapping.AccountIDEnv == "" {
					t.Fatalf("%s asset mapping missing", p)
				}
				if (p == RDP || p == VNC || p == Web) && mapping.URLTemplateEnv == "" {
					t.Fatalf("%s browser URL mapping missing", p)
				}
			}
		})
	}
}

func TestFormalScenarioExecutionModeCounts(t *testing.T) {
	want := map[string]map[Protocol]ModeCounts{
		"graphics-1000.yaml": {
			RDP: {Browser: 18, Direct: 482}, VNC: {Browser: 5, Direct: 145},
			Web: {Browser: 9, Direct: 241}, MySQL: {Direct: 100},
		},
		"mixed-1000.yaml": {
			SSH: {Direct: 600}, RDP: {Browser: 7, Direct: 193},
			VNC: {Browser: 2, Direct: 48}, Web: {Browser: 3, Direct: 97}, MySQL: {Direct: 50},
		},
	}
	for name, expected := range want {
		cfg, err := Load(filepath.Join("..", "..", "configs", name))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := cfg.Expand(); err != nil {
			t.Fatal(err)
		}
		for protocol, counts := range expected {
			if cfg.ExecutionModes[protocol] != counts {
				t.Fatalf("%s %s=%+v want %+v", name, protocol, cfg.ExecutionModes[protocol], counts)
			}
		}
	}
}

func TestMySQLBrowserScenarioFile(t *testing.T) {
	cfg, err := Load(filepath.Join("..", "..", "configs", "mysql-browser.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Total != 1 || cfg.Ramp != time.Second || cfg.Hold != 30*time.Second {
		t.Fatalf("runtime total=%d ramp=%s hold=%s", cfg.Total, cfg.Ramp, cfg.Hold)
	}
	if cfg.Protocols[MySQL] != 1 || cfg.ExecutionModes[MySQL] != (ModeCounts{Browser: 1}) {
		t.Fatalf("mysql protocol=%d mode=%+v", cfg.Protocols[MySQL], cfg.ExecutionModes[MySQL])
	}
	mapping := cfg.Assets[MySQL]
	if mapping.AssetIDEnv != "MYSQL_ASSET_ID" || mapping.AccountIDEnv != "MYSQL_ACCOUNT_ID" || mapping.URLTemplateEnv != "MYSQL_BROWSER_URL_TEMPLATE" {
		t.Fatalf("mysql mapping=%+v", mapping)
	}
}

func TestMixedStabilityScenarioFile(t *testing.T) {
	cfg, err := Load(filepath.Join("..", "..", "configs", "mixed-stability-45.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Total != 45 || cfg.Ramp != 5*time.Minute || cfg.Hold != 2*time.Hour || cfg.ConnectRetries != 3 || !cfg.ContinueOnErrors {
		t.Fatalf("runtime configuration=%+v", cfg)
	}
	wantProtocols := map[Protocol]int{SSH: 40, RDP: 2, VNC: 1, Web: 1, MySQL: 1}
	if !reflect.DeepEqual(cfg.Protocols, wantProtocols) {
		t.Fatalf("protocols=%v want=%v", cfg.Protocols, wantProtocols)
	}
	for protocol, want := range map[Protocol]time.Duration{SSH: 10 * time.Second, RDP: 3 * time.Second, VNC: 3 * time.Second, Web: 5 * time.Second, MySQL: 5 * time.Second} {
		if got := cfg.ActivityInterval(protocol); got != want {
			t.Fatalf("%s interval=%s want=%s", protocol, got, want)
		}
	}
	jobs, err := cfg.Expand()
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 45 {
		t.Fatalf("jobs=%d", len(jobs))
	}
}

func TestAssetMappingResolvesOnlyFromEnvironment(t *testing.T) {
	t.Setenv("SSH_ASSET_ID", "asset-runtime")
	t.Setenv("SSH_ACCOUNT_ID", "account-runtime")
	p := writeConfig(t, `name: one
total: 1
ramp: 1m
hold: 1m
protocols: {ssh: 1}
pam: {base_url: http://pam.test, username_env: PAM_USERNAME, password_env: PAM_PASSWORD}
assets:
  ssh: {asset_id_env: SSH_ASSET_ID, account_id_env: SSH_ACCOUNT_ID}
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	asset, account, _, err := cfg.Asset(SSH)
	if err != nil || asset != "asset-runtime" || account != "account-runtime" {
		t.Fatalf("asset=%q account=%q err=%v", asset, account, err)
	}
}
