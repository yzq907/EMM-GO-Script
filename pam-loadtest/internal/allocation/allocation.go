package allocation

import (
	"fmt"
	"hash/fnv"
	"math/rand"
	"sort"

	"pam-loadtest/internal/config"
	"pam-loadtest/internal/inventory"
)

type Summary struct {
	Planned    int
	ByProtocol map[config.Protocol]int
}

func Bind(jobs []config.Job, source inventory.Manifest, seed int64) ([]config.Job, Summary, error) {
	manifest := source
	manifest.Assets = append([]inventory.ManifestAsset(nil), source.Assets...)
	if err := inventory.ValidateManifest(&manifest); err != nil {
		return nil, Summary{}, err
	}
	pools := make(map[config.Protocol][]inventory.ManifestAsset)
	for _, asset := range manifest.Assets {
		protocol := config.Protocol(asset.Protocol)
		pools[protocol] = append(pools[protocol], asset)
	}
	requested := make(map[config.Protocol]int)
	seenJobs := make(map[int]struct{}, len(jobs))
	for _, job := range jobs {
		if job.ID < 1 {
			return nil, Summary{}, fmt.Errorf("job ID must be positive")
		}
		if _, exists := seenJobs[job.ID]; exists {
			return nil, Summary{}, fmt.Errorf("duplicate job ID")
		}
		seenJobs[job.ID] = struct{}{}
		if job.AssetID != "" || job.AccountID != "" {
			return nil, Summary{}, fmt.Errorf("job %d is already asset-bound", job.ID)
		}
		if !knownProtocol(job.Protocol) {
			return nil, Summary{}, fmt.Errorf("job %d has unsupported protocol", job.ID)
		}
		requested[job.Protocol]++
	}
	for protocol, count := range requested {
		if len(pools[protocol]) < count {
			return nil, Summary{}, fmt.Errorf("%s asset pool exhausted: available=%d requested=%d", protocol, len(pools[protocol]), count)
		}
	}
	for protocol, pool := range pools {
		sort.Slice(pool, func(i, j int) bool {
			if pool[i].Name == pool[j].Name {
				return pool[i].AssetID < pool[j].AssetID
			}
			return pool[i].Name < pool[j].Name
		})
		random := rand.New(rand.NewSource(seed ^ protocolSalt(protocol)))
		for i := len(pool) - 1; i > 0; i-- {
			j := random.Intn(i + 1)
			pool[i], pool[j] = pool[j], pool[i]
		}
		pools[protocol] = pool
	}
	positions := make(map[config.Protocol]int)
	bound := append([]config.Job(nil), jobs...)
	for index := range bound {
		position := positions[bound[index].Protocol]
		asset := pools[bound[index].Protocol][position]
		bound[index].AssetID = asset.AssetID
		bound[index].AccountID = asset.AccountID
		positions[bound[index].Protocol]++
	}
	return bound, Summary{Planned: len(bound), ByProtocol: requested}, nil
}

func protocolSalt(protocol config.Protocol) int64 {
	hash := fnv.New64a()
	_, _ = hash.Write([]byte(protocol))
	return int64(hash.Sum64())
}

func knownProtocol(protocol config.Protocol) bool {
	switch protocol {
	case config.SSH, config.RDP, config.VNC, config.Web, config.MySQL:
		return true
	default:
		return false
	}
}
