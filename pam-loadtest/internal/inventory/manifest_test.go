package inventory

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func writeManifestFixture(t *testing.T, manifest Manifest) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "manifest.json")
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadManifestValidatesRuntimeSchedulingFields(t *testing.T) {
	valid := Manifest{Version: 1, Assets: []ManifestAsset{
		{Name: "ssh-1", IP: "10.1.0.1", Protocol: "SSH", AssetID: "a-1", AccountID: "u-1"},
		{Name: "db-1", IP: "10.2.0.1", Protocol: "database", AssetID: "a-2", AccountID: "u-2"},
	}}
	manifest, err := LoadManifest(writeManifestFixture(t, valid))
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Assets[0].Protocol != "ssh" || manifest.Assets[1].Protocol != "mysql" {
		t.Fatalf("protocols=%q,%q", manifest.Assets[0].Protocol, manifest.Assets[1].Protocol)
	}
}

func TestLoadManifestRejectsInvalidRuntimeData(t *testing.T) {
	base := Manifest{Version: 1, Assets: []ManifestAsset{
		{Name: "one", IP: "10.1.0.1", Protocol: "ssh", AssetID: "a-1", AccountID: "u-1"},
		{Name: "two", IP: "10.1.0.2", Protocol: "rdp", AssetID: "a-2", AccountID: "u-2"},
	}}
	tests := map[string]func(*Manifest){
		"version":           func(m *Manifest) { m.Version = 2 },
		"empty assets":      func(m *Manifest) { m.Assets = nil },
		"missing name":      func(m *Manifest) { m.Assets[0].Name = "" },
		"missing ip":        func(m *Manifest) { m.Assets[0].IP = "" },
		"missing protocol":  func(m *Manifest) { m.Assets[0].Protocol = "" },
		"missing asset":     func(m *Manifest) { m.Assets[0].AssetID = "" },
		"missing account":   func(m *Manifest) { m.Assets[0].AccountID = "" },
		"unsupported":       func(m *Manifest) { m.Assets[0].Protocol = "telnet" },
		"duplicate name":    func(m *Manifest) { m.Assets[1].Name = m.Assets[0].Name },
		"duplicate ip":      func(m *Manifest) { m.Assets[1].IP = m.Assets[0].IP },
		"duplicate asset":   func(m *Manifest) { m.Assets[1].AssetID = m.Assets[0].AssetID },
		"duplicate account": func(m *Manifest) { m.Assets[1].AccountID = m.Assets[0].AccountID },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			manifest := base
			manifest.Assets = append([]ManifestAsset(nil), base.Assets...)
			mutate(&manifest)
			if _, err := LoadManifest(writeManifestFixture(t, manifest)); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestLoadManifestRejectsUnknownFieldsAndTrailingJSON(t *testing.T) {
	for name, body := range map[string]string{
		"unknown":  `{"version":1,"assets":[],"password":"forbidden"}`,
		"trailing": `{"version":1,"assets":[]} {}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "manifest.json")
			if err := os.WriteFile(path, []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadManifest(path); err == nil {
				t.Fatal("expected parse error")
			}
		})
	}
}

func TestWriteManifestUsesRestrictedModeAndNeverSerializesSecrets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manifest.json")
	manifest := Manifest{Version: 1, Assets: []ManifestAsset{{Name: "generated", IP: "10.200.0.1", Protocol: "ssh", AssetID: "asset-id", AccountID: "account-id"}}}
	if err := WriteManifest(path, manifest); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lower := strings.ToLower(string(raw))
	for _, forbidden := range []string{"password", "cookie", "token"} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("manifest contains forbidden field %q", forbidden)
		}
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0600 {
			t.Fatalf("mode = %o, want 600", got)
		}
	}
}

func TestBuildManifestRequiresUniqueAssetAndAccountIDs(t *testing.T) {
	remote := []RemoteAsset{
		{ID: "same", Name: GeneratedPrefix + "one", Description: GeneratedMarker, IP: "10.200.0.1", Protocol: "ssh", DefaultAccountID: "account-one"},
		{ID: "same", Name: GeneratedPrefix + "two", Description: GeneratedMarker, IP: "10.200.0.2", Protocol: "ssh", DefaultAccountID: "account-two"},
	}
	if _, err := BuildManifest(remote); err == nil || !strings.Contains(err.Error(), "asset ID") {
		t.Fatalf("error = %v", err)
	}
	remote[1].ID = "asset-two"
	remote[1].DefaultAccountID = "account-one"
	if _, err := BuildManifest(remote); err == nil || !strings.Contains(err.Error(), "account ID") {
		t.Fatalf("error = %v", err)
	}
}

func TestBuildManifestForMarkersIncludesBaseAndExtensionOnly(t *testing.T) {
	remote := []RemoteAsset{
		{ID: "base", Name: GeneratedPrefix + "one", Description: GeneratedMarker, IP: "10.200.0.1", Protocol: "ssh", DefaultAccountID: "base-account"},
		{ID: "extension", Name: ExtensionPrefix + "one", Description: ExtensionMarker, IP: "10.200.8.1", Protocol: "rdp", DefaultAccountID: "extension-account"},
		{ID: "other", Name: "unmanaged", Description: "unmanaged", IP: "192.0.2.1", Protocol: "ssh", DefaultAccountID: "other-account"},
	}
	manifest, err := BuildManifestForMarkers(remote, []string{GeneratedMarker, ExtensionMarker})
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Assets) != 2 {
		t.Fatalf("assets=%+v", manifest.Assets)
	}
	if _, err := BuildManifestForMarkers(remote, nil); err == nil {
		t.Fatal("expected empty marker rejection")
	}
}
