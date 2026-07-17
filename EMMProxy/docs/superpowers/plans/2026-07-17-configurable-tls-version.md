# Configurable TLS Version Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `tls_version` configuration field that forces the load tester to use exactly TLS 1.2 or exactly TLS 1.3 while preserving all existing load and session behavior.

**Architecture:** Keep the existing flat `Config` structure and central `loadConfig` initialization path. A small parser will normalize and validate the configured string, then provide the Go TLS version constant used for both `MinVersion` and `MaxVersion`; the rest of the connection flow remains unchanged.

**Tech Stack:** Go standard library (`crypto/tls`, `encoding/json`, `testing`), JSON configuration.

---

## File Structure

- `main.go`: add `Config.TLSVersion`, parse and validate it, force `tls.Config` to the selected exact version, and log the selected version once at startup.
- `main_test.go`: test default TLS 1.2 behavior, explicit TLS 1.2, explicit TLS 1.3, and invalid values.
- `config.json`: select TLS 1.2 for the current environment.
- `config.example.json`: document the backward-compatible TLS 1.2 default.

### Task 1: Lock Down TLS Version Parsing

**Files:**
- Modify: `main_test.go`
- Modify: `main.go`

- [ ] **Step 1: Write the failing table-driven test**

Append this test to `main_test.go`:

```go
func TestParseTLSVersion(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantName    string
		wantVersion uint16
		wantErr     bool
	}{
		{name: "default", input: "", wantName: "1.2", wantVersion: tls.VersionTLS12},
		{name: "tls12", input: "1.2", wantName: "1.2", wantVersion: tls.VersionTLS12},
		{name: "tls13", input: "1.3", wantName: "1.3", wantVersion: tls.VersionTLS13},
		{name: "invalid", input: "auto", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotName, gotVersion, err := parseTLSVersion(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatal("parseTLSVersion returned nil error")
				}
				return
			}
			if err != nil {
				t.Fatalf("parseTLSVersion returned error: %v", err)
			}
			if gotName != tt.wantName || gotVersion != tt.wantVersion {
				t.Fatalf("parseTLSVersion(%q) = (%q, %#x), want (%q, %#x)", tt.input, gotName, gotVersion, tt.wantName, tt.wantVersion)
			}
		})
	}
}
```

Add `"crypto/tls"` to the test imports.

- [ ] **Step 2: Run the focused test and verify it fails**

Run:

```bash
GOCACHE=/tmp/go-build-cache go test -count=1 -run '^TestParseTLSVersion$' ./...
```

Expected: build failure containing `undefined: parseTLSVersion`.

- [ ] **Step 3: Implement the minimal parser**

Add this helper near the other configuration helpers in `main.go`:

```go
func parseTLSVersion(value string) (string, uint16, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		value = "1.2"
	}

	switch value {
	case "1.2":
		return value, tls.VersionTLS12, nil
	case "1.3":
		return value, tls.VersionTLS13, nil
	default:
		return "", 0, fmt.Errorf("tls_version 仅支持 1.2 或 1.3，当前值: %q", value)
	}
}
```

- [ ] **Step 4: Run the focused test and verify it passes**

Run:

```bash
GOCACHE=/tmp/go-build-cache go test -count=1 -run '^TestParseTLSVersion$' ./...
```

Expected: `ok EMMProxy`.

- [ ] **Step 5: Commit the parser and tests**

```bash
git add main.go main_test.go
git commit -m "Add TLS version configuration parser"
```

### Task 2: Apply the Selected Version to TLS Connections

**Files:**
- Modify: `main.go`
- Modify: `main_test.go`

- [ ] **Step 1: Write a failing loadConfig integration test**

Add a test that writes a minimal temporary JSON file, loads it, and verifies exact TLS 1.3 selection:

```go
func TestLoadConfigForcesConfiguredTLSVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	content := []byte(`{
		"host":"127.0.0.1",
		"port":"8002",
		"request_host":"127.0.0.1",
		"request_port":"8090",
		"request_path":"/status",
		"tls_version":"1.3"
	}`)
	if err := os.WriteFile(path, content, 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	config, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig returned error: %v", err)
	}
	if config.TLSVersion != "1.3" {
		t.Fatalf("TLSVersion = %q, want 1.3", config.TLSVersion)
	}
	if config.TLSConfig.MinVersion != tls.VersionTLS13 || config.TLSConfig.MaxVersion != tls.VersionTLS13 {
		t.Fatalf("TLS version range = %#x-%#x, want TLS 1.3 only", config.TLSConfig.MinVersion, config.TLSConfig.MaxVersion)
	}
}
```

- [ ] **Step 2: Run the focused test and verify it fails**

Run:

```bash
GOCACHE=/tmp/go-build-cache go test -count=1 -run '^TestLoadConfigForcesConfiguredTLSVersion$' ./...
```

Expected: build failure because `Config.TLSVersion` does not exist.

- [ ] **Step 3: Add and apply the configuration field**

Add the field to `Config`:

```go
TLSVersion string `json:"tls_version"`
```

Before creating `tls.Config`, parse and store the normalized value:

```go
tlsVersionName, tlsVersion, err := parseTLSVersion(config.TLSVersion)
if err != nil {
	return nil, err
}
config.TLSVersion = tlsVersionName
```

Replace the hard-coded version range with:

```go
MinVersion: tlsVersion,
MaxVersion: tlsVersion,
```

After configuration loading succeeds in `main`, log the forced version once:

```go
log.Printf("强制使用 TLS %s", config.TLSVersion)
```

- [ ] **Step 4: Run the focused test and full unit suite**

Run:

```bash
GOCACHE=/tmp/go-build-cache go test -count=1 -run '^TestLoadConfigForcesConfiguredTLSVersion$' ./...
GOCACHE=/tmp/go-build-cache go test -count=1 ./...
```

Expected: both commands report `ok EMMProxy`.

- [ ] **Step 5: Commit TLS configuration application**

```bash
git add main.go main_test.go
git commit -m "Force configured TLS protocol version"
```

### Task 3: Update Configuration Examples and Verify

**Files:**
- Modify: `config.json`
- Modify: `config.example.json`

- [ ] **Step 1: Add the selected version to both JSON files**

Add this field immediately after `port` in both files:

```json
"tls_version": "1.2",
```

- [ ] **Step 2: Validate JSON and run all static checks**

Run:

```bash
python3 -m json.tool config.json >/dev/null
python3 -m json.tool config.example.json >/dev/null
GOCACHE=/tmp/go-build-cache go test -race -count=1 ./...
GOCACHE=/tmp/go-build-cache go vet ./...
```

Expected: both JSON commands exit zero, race tests report `ok EMMProxy`, and `go vet` emits no diagnostics.

- [ ] **Step 3: Runtime-verify TLS 1.2 without changing session data**

Create an isolated runtime directory containing the built program, the current config with `tls_version` set to `1.2`, and the known valid test session. Run for one second and verify successful requests against `10.10.27.216`; the startup log must state `强制使用 TLS 1.2`.

- [ ] **Step 4: Runtime-verify TLS 1.3 selection**

In the isolated runtime directory only, set `tls_version` to `1.3` and run against a server that supports TLS 1.3. Verify the startup log states `强制使用 TLS 1.3`; report business success or server rejection separately from configuration correctness.

- [ ] **Step 5: Review the final diff and commit configuration files**

Run:

```bash
git diff --check
git diff -- main.go main_test.go config.example.json
```

Then commit tracked configuration documentation:

```bash
git add config.example.json
git commit -m "Document TLS version configuration"
```

`config.json` may be ignored or environment-local; leave it updated in the workspace even if Git does not track it.
