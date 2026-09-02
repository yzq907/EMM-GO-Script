package distributed

import (
	"fmt"
	"strings"
	"testing"

	"pam-loadtest/internal/config"
)

var allDirect = []config.Protocol{config.SSH, config.RDP, config.VNC, config.Web, config.MySQL}

func TestPartitionIsDeterministicAndHonorsCapacity(t *testing.T) {
	jobs := make([]config.Job, 10)
	for i := range jobs {
		jobs[i] = config.Job{ID: i + 1, Protocol: config.SSH, Mode: config.Direct, AssetID: fmt.Sprintf("asset-%d", i+1), AccountID: fmt.Sprintf("account-%d", i+1)}
	}
	agents := []Agent{{ID: "a", Capacity: 4, DirectProtocols: allDirect}, {ID: "b", Capacity: 6, DirectProtocols: allDirect}}
	one, err := Partition(jobs, agents)
	if err != nil {
		t.Fatal(err)
	}
	two, _ := Partition(jobs, agents)
	if len(one["a"]) != 4 || len(one["b"]) != 6 {
		t.Fatalf("assignment=%v", one)
	}
	seen := map[string]bool{}
	for id := range one {
		for i := range one[id] {
			if one[id][i] != two[id][i] {
				t.Fatal("partition is not deterministic")
			}
			if seen[one[id][i].AssetID] {
				t.Fatal("asset assigned to multiple agents")
			}
			seen[one[id][i].AssetID] = true
		}
	}
}

func TestPartitionRejectsInsufficientCapacity(t *testing.T) {
	jobs := []config.Job{{ID: 1, Protocol: config.SSH}, {ID: 2, Protocol: config.SSH}}
	if _, err := Partition(jobs, []Agent{{ID: "a", Capacity: 1}}); err == nil {
		t.Fatal("expected capacity error")
	}
}

func TestPartitionBalancesGraphicalHybridAcrossFourAgents(t *testing.T) {
	cfg := config.Config{
		Total:     1000,
		Protocols: map[config.Protocol]int{config.RDP: 500, config.VNC: 150, config.Web: 250, config.MySQL: 100},
		ExecutionModes: map[config.Protocol]config.ModeCounts{
			config.RDP: {Browser: 18, Direct: 482}, config.VNC: {Browser: 5, Direct: 145}, config.Web: {Browser: 9, Direct: 241}, config.MySQL: {Direct: 100},
		},
	}
	jobs, err := cfg.Expand()
	if err != nil {
		t.Fatal(err)
	}
	for i := range jobs {
		jobs[i].AssetID = fmt.Sprintf("asset-%d", i)
		jobs[i].AccountID = fmt.Sprintf("account-%d", i)
	}
	agents := []Agent{
		{ID: "a", Capacity: 250, DirectCapacity: 250, BrowserCapacity: 8, DirectProtocols: allDirect},
		{ID: "b", Capacity: 250, DirectCapacity: 250, BrowserCapacity: 8, DirectProtocols: allDirect},
		{ID: "c", Capacity: 250, DirectCapacity: 250, BrowserCapacity: 8, DirectProtocols: allDirect},
		{ID: "d", Capacity: 250, DirectCapacity: 250, BrowserCapacity: 8, DirectProtocols: allDirect},
	}
	assignments, err := Partition(jobs, agents)
	if err != nil {
		t.Fatal(err)
	}
	for _, agent := range agents {
		browser := 0
		for _, job := range assignments[agent.ID] {
			if job.Mode == config.Browser {
				browser++
			}
		}
		if len(assignments[agent.ID]) != 250 || browser != 8 {
			t.Fatalf("agent=%s jobs=%d browser=%d", agent.ID, len(assignments[agent.ID]), browser)
		}
	}
}

func TestPartitionBalancesMixedHybridAcrossFourAgents(t *testing.T) {
	cfg := config.Config{
		Total:     1000,
		Protocols: map[config.Protocol]int{config.SSH: 600, config.RDP: 200, config.VNC: 50, config.Web: 100, config.MySQL: 50},
		ExecutionModes: map[config.Protocol]config.ModeCounts{
			config.SSH: {Direct: 600}, config.RDP: {Browser: 7, Direct: 193}, config.VNC: {Browser: 2, Direct: 48}, config.Web: {Browser: 3, Direct: 97}, config.MySQL: {Direct: 50},
		},
	}
	jobs, err := cfg.Expand()
	if err != nil {
		t.Fatal(err)
	}
	for i := range jobs {
		jobs[i].AssetID = fmt.Sprintf("asset-%d", i)
		jobs[i].AccountID = fmt.Sprintf("account-%d", i)
	}
	agents := []Agent{
		{ID: "a", Capacity: 250, DirectCapacity: 250, BrowserCapacity: 3, DirectProtocols: allDirect},
		{ID: "b", Capacity: 250, DirectCapacity: 250, BrowserCapacity: 3, DirectProtocols: allDirect},
		{ID: "c", Capacity: 250, DirectCapacity: 250, BrowserCapacity: 3, DirectProtocols: allDirect},
		{ID: "d", Capacity: 250, DirectCapacity: 250, BrowserCapacity: 3, DirectProtocols: allDirect},
	}
	assignments, err := Partition(jobs, agents)
	if err != nil {
		t.Fatal(err)
	}
	for _, agent := range agents {
		browser := 0
		for _, job := range assignments[agent.ID] {
			if job.Mode == config.Browser {
				browser++
			}
		}
		if len(assignments[agent.ID]) != 250 || browser != 3 {
			t.Fatalf("agent=%s jobs=%d browser=%d", agent.ID, len(assignments[agent.ID]), browser)
		}
	}
}

func TestPartitionRejectsInsufficientBrowserCapacity(t *testing.T) {
	jobs := []config.Job{{ID: 1, Protocol: config.RDP, Mode: config.Browser, AssetID: "a", AccountID: "u"}}
	_, err := Partition(jobs, []Agent{{ID: "one", Capacity: 10, DirectCapacity: 10, BrowserCapacity: 0}})
	if err == nil || !strings.Contains(err.Error(), "browser capacity") {
		t.Fatalf("err=%v", err)
	}
}

func TestPartitionRejectsMissingExecutionMode(t *testing.T) {
	job := config.Job{ID: 1, Protocol: config.SSH, AssetID: "asset", AccountID: "account"}
	if _, err := Partition([]config.Job{job}, []Agent{{ID: "agent", Capacity: 1, DirectCapacity: 1}}); err == nil || !strings.Contains(err.Error(), "execution mode") {
		t.Fatalf("err=%v", err)
	}
}

func TestPartitionHonorsPerAgentDirectProtocolCapabilities(t *testing.T) {
	jobs := []config.Job{
		{ID: 1, Protocol: config.SSH, Mode: config.Direct, AssetID: "asset-1", AccountID: "account-1"},
		{ID: 2, Protocol: config.MySQL, Mode: config.Direct, AssetID: "asset-2", AccountID: "account-2"},
	}
	agents := []Agent{
		{ID: "mysql-only", Capacity: 1, DirectCapacity: 1, DirectProtocols: []config.Protocol{config.MySQL}},
		{ID: "ssh-only", Capacity: 1, DirectCapacity: 1, DirectProtocols: []config.Protocol{config.SSH}},
	}
	assignments, err := Partition(jobs, agents)
	if err != nil {
		t.Fatal(err)
	}
	if assignments["mysql-only"][0].Protocol != config.MySQL || assignments["ssh-only"][0].Protocol != config.SSH {
		t.Fatalf("assignments=%+v", assignments)
	}
	if _, err := Partition(jobs[:1], []Agent{{ID: "mysql-only", Capacity: 1, DirectCapacity: 1, DirectProtocols: []config.Protocol{config.MySQL}}}); err == nil {
		t.Fatal("expected unsupported direct protocol rejection")
	}
}

func TestPartitionFindsFeasibleAssignmentForScarceDirectProtocol(t *testing.T) {
	jobs := []config.Job{
		{ID: 1, Protocol: config.SSH, Mode: config.Direct, AssetID: "asset-1", AccountID: "account-1"},
		{ID: 2, Protocol: config.RDP, Mode: config.Direct, AssetID: "asset-2", AccountID: "account-2"},
	}
	agents := []Agent{
		{ID: "flexible", Capacity: 1, DirectCapacity: 1, DirectProtocols: []config.Protocol{config.SSH, config.RDP}},
		{ID: "ssh-only", Capacity: 1, DirectCapacity: 1, DirectProtocols: []config.Protocol{config.SSH}},
	}
	assignments, err := Partition(jobs, agents)
	if err != nil {
		t.Fatal(err)
	}
	if assignments["flexible"][0].Protocol != config.RDP || assignments["ssh-only"][0].Protocol != config.SSH {
		t.Fatalf("assignments=%+v", assignments)
	}
}

func TestPartitionTreatsEmptyDirectProtocolCapabilityAsUnsupported(t *testing.T) {
	job := config.Job{ID: 1, Protocol: config.SSH, Mode: config.Direct, AssetID: "asset", AccountID: "account"}
	if _, err := Partition([]config.Job{job}, []Agent{{ID: "agent", Capacity: 1, DirectCapacity: 1}}); err == nil {
		t.Fatal("expected empty direct capability rejection")
	}
}
