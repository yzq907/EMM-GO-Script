package inventory

import (
	"context"
	"fmt"
)

type InventoryAPI interface {
	ListAssets(context.Context) ([]RemoteAsset, error)
	ImportAssets(context.Context, []Asset, ImportCredentials) error
}

type ApplyOptions struct {
	Execute     bool
	Limit       int
	BatchSize   int
	Credentials ImportCredentials
}

type ApplyReport struct {
	Desired  int `json:"desired"`
	Existing int `json:"existing"`
	Pending  int `json:"pending"`
	Created  int `json:"created"`
}

func Apply(ctx context.Context, api InventoryAPI, desired []Asset, options ApplyOptions) (ApplyReport, error) {
	if options.Limit > 0 && len(desired) > options.Limit {
		desired = desired[:options.Limit]
	}
	report := ApplyReport{Desired: len(desired)}
	existing, err := api.ListAssets(ctx)
	if err != nil {
		return report, err
	}
	missing, existingCount, err := reconcile(desired, existing)
	report.Existing = existingCount
	report.Pending = len(missing)
	if err != nil || !options.Execute {
		return report, err
	}
	batchSize := options.BatchSize
	if batchSize < 1 || batchSize > 50 {
		batchSize = 50
	}
	for start := 0; start < len(missing); start += batchSize {
		end := start + batchSize
		if end > len(missing) {
			end = len(missing)
		}
		batch := missing[start:end]
		if err := api.ImportAssets(ctx, batch, options.Credentials); err != nil {
			return report, fmt.Errorf("import batch beginning with %s: %w", batch[0].Name, err)
		}
		current, err := api.ListAssets(ctx)
		if err != nil {
			return report, err
		}
		unresolved, exact, err := reconcile(batch, current)
		if err != nil {
			return report, err
		}
		if len(unresolved) != 0 || exact != len(batch) {
			return report, fmt.Errorf("import reconciliation failed for batch beginning with %s", batch[0].Name)
		}
		report.Created += len(batch)
		report.Pending -= len(batch)
	}
	return report, nil
}

func reconcile(desired []Asset, existing []RemoteAsset) ([]Asset, int, error) {
	byName := make(map[string][]RemoteAsset)
	byIP := make(map[string][]RemoteAsset)
	for _, asset := range existing {
		byName[asset.Name] = append(byName[asset.Name], asset)
		byIP[asset.IP] = append(byIP[asset.IP], asset)
	}
	missing := make([]Asset, 0)
	exact := 0
	for _, wanted := range desired {
		nameMatches := byName[wanted.Name]
		if len(nameMatches) > 1 {
			return nil, exact, fmt.Errorf("conflict: multiple assets named %s", wanted.Name)
		}
		if len(nameMatches) == 1 {
			found := nameMatches[0]
			if !remoteMatches(wanted, found) {
				return nil, exact, fmt.Errorf("conflict: existing asset named %s does not match generated record", wanted.Name)
			}
			exact++
			continue
		}
		if matches := byIP[wanted.IP]; len(matches) != 0 {
			return nil, exact, fmt.Errorf("conflict: address %s is already assigned", wanted.IP)
		}
		missing = append(missing, wanted)
	}
	return missing, exact, nil
}

func remoteMatches(wanted Asset, found RemoteAsset) bool {
	return found.Description == wanted.Marker && found.IP == wanted.IP && found.Protocol == wanted.Protocol && normalizeDBType(found.DBType) == normalizeDBType(wanted.DBType) && found.Port == wanted.Port && found.ID != "" && found.AccountCount == 1 && found.DefaultAccountID != ""
}

func normalizeDBType(value string) string {
	if value == "-" {
		return ""
	}
	return value
}
