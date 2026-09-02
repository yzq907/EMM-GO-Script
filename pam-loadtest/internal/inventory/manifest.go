package inventory

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type Manifest struct {
	Version int             `json:"version"`
	Assets  []ManifestAsset `json:"assets"`
}

type ManifestAsset struct {
	Name      string `json:"name"`
	IP        string `json:"ip"`
	Protocol  string `json:"protocol"`
	AssetID   string `json:"assetId"`
	AccountID string `json:"accountId"`
}

func LoadManifest(path string) (Manifest, error) {
	file, err := os.Open(path)
	if err != nil {
		return Manifest{}, fmt.Errorf("open asset manifest: %w", err)
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 16<<20))
	decoder.DisallowUnknownFields()
	var manifest Manifest
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, fmt.Errorf("parse asset manifest: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			err = fmt.Errorf("multiple JSON values")
		}
		return Manifest{}, fmt.Errorf("parse asset manifest: %w", err)
	}
	if err := ValidateManifest(&manifest); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func ValidateManifest(manifest *Manifest) error {
	if manifest == nil {
		return fmt.Errorf("asset manifest is nil")
	}
	if manifest.Version != 1 {
		return fmt.Errorf("unsupported asset manifest version")
	}
	if len(manifest.Assets) == 0 {
		return fmt.Errorf("asset manifest is empty")
	}
	seenNames := make(map[string]struct{}, len(manifest.Assets))
	seenIPs := make(map[string]struct{}, len(manifest.Assets))
	seenAssets := make(map[string]struct{}, len(manifest.Assets))
	seenAccounts := make(map[string]struct{}, len(manifest.Assets))
	for index := range manifest.Assets {
		asset := &manifest.Assets[index]
		asset.Name = strings.TrimSpace(asset.Name)
		asset.IP = strings.TrimSpace(asset.IP)
		asset.AssetID = strings.TrimSpace(asset.AssetID)
		asset.AccountID = strings.TrimSpace(asset.AccountID)
		asset.Protocol = strings.ToLower(strings.TrimSpace(asset.Protocol))
		if asset.Protocol == "database" {
			asset.Protocol = "mysql"
		}
		for field, value := range map[string]string{
			"name": asset.Name, "IP": asset.IP, "protocol": asset.Protocol,
			"asset ID": asset.AssetID, "account ID": asset.AccountID,
		} {
			if value == "" {
				return fmt.Errorf("asset manifest record %d has empty %s", index+1, field)
			}
		}
		switch asset.Protocol {
		case "ssh", "rdp", "vnc", "web", "mysql":
		default:
			return fmt.Errorf("asset manifest record %d has unsupported protocol", index+1)
		}
		for field, item := range map[string]struct {
			value string
			seen  map[string]struct{}
		}{
			"name": {asset.Name, seenNames}, "IP": {asset.IP, seenIPs},
			"asset ID": {asset.AssetID, seenAssets}, "account ID": {asset.AccountID, seenAccounts},
		} {
			if _, ok := item.seen[item.value]; ok {
				return fmt.Errorf("asset manifest record %d has duplicate %s", index+1, field)
			}
			item.seen[item.value] = struct{}{}
		}
	}
	return nil
}

func BuildManifest(remote []RemoteAsset) (Manifest, error) {
	return BuildManifestForMarkers(remote, []string{GeneratedMarker})
}

func BuildManifestForMarkers(remote []RemoteAsset, markers []string) (Manifest, error) {
	manifest := Manifest{Version: 1}
	allowed := make(map[string]struct{}, len(markers))
	for _, marker := range markers {
		marker = strings.TrimSpace(marker)
		if marker != "" {
			allowed[marker] = struct{}{}
		}
	}
	if len(allowed) == 0 {
		return Manifest{}, fmt.Errorf("at least one generated marker is required")
	}
	names := make(map[string]bool)
	addresses := make(map[string]bool)
	assetIDs := make(map[string]bool)
	accountIDs := make(map[string]bool)
	for _, asset := range remote {
		if _, ok := allowed[asset.Description]; !ok {
			continue
		}
		if asset.ID == "" || assetIDs[asset.ID] {
			return Manifest{}, fmt.Errorf("missing or duplicate asset ID for %s", asset.Name)
		}
		if asset.DefaultAccountID == "" || accountIDs[asset.DefaultAccountID] {
			return Manifest{}, fmt.Errorf("missing or duplicate account ID for %s", asset.Name)
		}
		if names[asset.Name] || addresses[asset.IP] {
			return Manifest{}, fmt.Errorf("duplicate generated name or address for %s", asset.Name)
		}
		names[asset.Name], addresses[asset.IP] = true, true
		assetIDs[asset.ID], accountIDs[asset.DefaultAccountID] = true, true
		manifest.Assets = append(manifest.Assets, ManifestAsset{Name: asset.Name, IP: asset.IP, Protocol: asset.Protocol, AssetID: asset.ID, AccountID: asset.DefaultAccountID})
	}
	sort.Slice(manifest.Assets, func(i, j int) bool { return manifest.Assets[i].Name < manifest.Assets[j].Name })
	return manifest, nil
}

func WriteManifest(path string, manifest Manifest) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	writeErr := encoder.Encode(manifest)
	closeErr := file.Close()
	if writeErr != nil {
		return writeErr
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Chmod(path, 0600)
}
