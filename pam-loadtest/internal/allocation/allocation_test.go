package allocation

import (
	"reflect"
	"strings"
	"testing"

	"pam-loadtest/internal/config"
	"pam-loadtest/internal/inventory"
)

func manifestFixture(counts map[config.Protocol]int) inventory.Manifest {
	manifest := inventory.Manifest{Version: 1}
	index := 0
	for _, protocol := range []config.Protocol{config.SSH, config.RDP, config.VNC, config.Web, config.MySQL} {
		for i := 0; i < counts[protocol]; i++ {
			index++
			manifest.Assets = append(manifest.Assets, inventory.ManifestAsset{
				Name:      string(protocol) + "-asset-" + string(rune('a'+i)),
				IP:        "10.200.0." + string(rune('a'+index)),
				Protocol:  string(protocol),
				AssetID:   string(protocol) + "-asset-id-" + string(rune('a'+i)),
				AccountID: string(protocol) + "-account-id-" + string(rune('a'+i)),
			})
		}
	}
	return manifest
}

func jobsFixture(counts map[config.Protocol]int) []config.Job {
	var jobs []config.Job
	for _, protocol := range []config.Protocol{config.SSH, config.RDP, config.VNC, config.Web, config.MySQL} {
		for i := 0; i < counts[protocol]; i++ {
			jobs = append(jobs, config.Job{ID: len(jobs) + 1, Protocol: protocol})
		}
	}
	return jobs
}

func TestBindAllocatesExactUniqueProtocolAssetsDeterministically(t *testing.T) {
	counts := map[config.Protocol]int{config.SSH: 6, config.RDP: 2, config.VNC: 2, config.Web: 1, config.MySQL: 1}
	manifest := manifestFixture(map[config.Protocol]int{config.SSH: 8, config.RDP: 3, config.VNC: 3, config.Web: 2, config.MySQL: 2})
	jobs := jobsFixture(counts)
	one, summary, err := Bind(jobs, manifest, 42)
	if err != nil {
		t.Fatal(err)
	}
	two, _, err := Bind(jobs, manifest, 42)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(one, two) {
		t.Fatal("same seed did not produce identical allocation")
	}
	if summary.Planned != len(jobs) || !reflect.DeepEqual(summary.ByProtocol, counts) {
		t.Fatalf("summary=%+v", summary)
	}
	seenAssets := map[string]bool{}
	seenAccounts := map[string]bool{}
	for _, job := range one {
		if job.AssetID == "" || job.AccountID == "" {
			t.Fatalf("job is not bound: %+v", job)
		}
		if seenAssets[job.AssetID] || seenAccounts[job.AccountID] {
			t.Fatalf("duplicate binding for job %d", job.ID)
		}
		seenAssets[job.AssetID], seenAccounts[job.AccountID] = true, true
		if !strings.HasPrefix(job.AssetID, string(job.Protocol)+"-") {
			t.Fatalf("job %d received wrong protocol asset", job.ID)
		}
	}
	other, _, err := Bind(jobs, manifest, 43)
	if err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(one, other) {
		t.Fatal("different seed did not change allocation")
	}
}

func TestBindRejectsExhaustionBeforeReturningPartialJobs(t *testing.T) {
	jobs := jobsFixture(map[config.Protocol]int{config.SSH: 2, config.RDP: 2})
	manifest := manifestFixture(map[config.Protocol]int{config.SSH: 2, config.RDP: 1})
	bound, _, err := Bind(jobs, manifest, 42)
	if err == nil || !strings.Contains(err.Error(), "rdp") || len(bound) != 0 {
		t.Fatalf("bound=%v err=%v", bound, err)
	}
}

func TestBindRejectsAlreadyBoundOrInvalidManifest(t *testing.T) {
	manifest := manifestFixture(map[config.Protocol]int{config.SSH: 2})
	jobs := jobsFixture(map[config.Protocol]int{config.SSH: 1})
	jobs[0].AssetID = "already-bound"
	if _, _, err := Bind(jobs, manifest, 1); err == nil {
		t.Fatal("expected already-bound job rejection")
	}
	jobs[0].AssetID = ""
	manifest.Assets[1].AssetID = manifest.Assets[0].AssetID
	if _, _, err := Bind(jobs, manifest, 1); err == nil {
		t.Fatal("expected invalid manifest rejection")
	}
}
