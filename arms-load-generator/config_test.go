package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const validConfigJSON = `{
  "host": "127.0.0.1:8104",
  "threads": 128,
  "duration": "10m",
  "target_tps": 25000,
  "ramp_up": "30s",
  "connect_timeout": "5s",
  "write_timeout": "3s",
  "heartbeat_interval": "30s",
  "stats_interval": "1s",
  "results_file": "results.csv",
  "app_name": "com.enterprise.h5.armsLoadTest",
  "server_id": 8410,
  "username_prefix": "loadtest",
  "session_prefix": "si:arms-load-test-",
  "client_ip": "10.8.83.146",
  "server_address": "10.10.27.172:8089",
  "request_method": "GET",
  "request_path": "/status",
  "request_host": "10.10.27.172:8089",
  "response_status": 200,
  "response_body": "ARMS load test success"
}`

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadConfig(t *testing.T) {
	config, err := LoadConfig(writeConfig(t, validConfigJSON))
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}
	if config.Threads != 128 || config.TargetTPS != 25000 {
		t.Fatalf("unexpected load settings: threads=%d target=%d", config.Threads, config.TargetTPS)
	}
	if config.Duration != 10*time.Minute || config.RampUp != 30*time.Second {
		t.Fatalf("unexpected durations: duration=%s ramp=%s", config.Duration, config.RampUp)
	}
	if config.HighThreadWarning() {
		t.Fatal("128 threads must not trigger high thread warning")
	}
}

func TestLoadConfigRejectsInvalidFields(t *testing.T) {
	tests := []struct {
		name    string
		old     string
		new     string
		wantErr string
	}{
		{name: "host", old: `"host": "127.0.0.1:8104"`, new: `"host": ""`, wantErr: "host"},
		{name: "threads zero", old: `"threads": 128`, new: `"threads": 0`, wantErr: "threads"},
		{name: "threads high", old: `"threads": 128`, new: `"threads": 25001`, wantErr: "threads"},
		{name: "negative tps", old: `"target_tps": 25000`, new: `"target_tps": -1`, wantErr: "target_tps"},
		{name: "duration", old: `"duration": "10m"`, new: `"duration": "0s"`, wantErr: "duration"},
		{name: "timeout", old: `"write_timeout": "3s"`, new: `"write_timeout": "invalid"`, wantErr: "write_timeout"},
		{name: "response body size", old: `"response_body": "ARMS load test success"`, new: `"response_body": "ARMS load test success", "response_body_size": -1`, wantErr: "response_body_size"},
		{name: "response chunk size", old: `"response_body": "ARMS load test success"`, new: `"response_body": "ARMS load test success", "response_chunk_size": -1`, wantErr: "response_chunk_size"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			content := strings.Replace(validConfigJSON, test.old, test.new, 1)
			_, err := LoadConfig(writeConfig(t, content))
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("LoadConfig() error = %v, want field %q", err, test.wantErr)
			}
		})
	}
}

func TestHighThreadWarning(t *testing.T) {
	content := strings.Replace(validConfigJSON, `"threads": 128`, `"threads": 20001`, 1)
	config, err := LoadConfig(writeConfig(t, content))
	if err != nil {
		t.Fatal(err)
	}
	if !config.HighThreadWarning() {
		t.Fatal("20001 threads must trigger high thread warning")
	}
}
