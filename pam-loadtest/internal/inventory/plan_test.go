package inventory

import (
	"encoding/json"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func TestDefaultPlanHasExactProtocolTotals(t *testing.T) {
	assets, err := Plan(DefaultSpec())
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]int{"ssh": 1000, "rdp": 400, "vnc": 200, "web": 200, "database": 200}
	got := make(map[string]int)
	for _, asset := range assets {
		got[asset.Protocol]++
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("protocol totals = %#v, want %#v", got, want)
	}
	if len(assets) != 2000 {
		t.Fatalf("asset count = %d, want 2000", len(assets))
	}
}

func TestDefaultPlanAllocatesEveryNodeEvenly(t *testing.T) {
	assets, err := Plan(DefaultSpec())
	if err != nil {
		t.Fatal(err)
	}

	type counts map[string]int
	got := make(map[string]counts)
	for _, asset := range assets {
		if got[asset.Backend] == nil {
			got[asset.Backend] = counts{}
		}
		got[asset.Backend][asset.Protocol]++
	}
	wantPerNode := counts{"ssh": 250, "rdp": 100, "vnc": 50, "web": 50, "database": 50}
	for _, backend := range []string{"10.19.88.145", "10.19.88.146", "10.19.88.147", "10.19.88.149"} {
		if !reflect.DeepEqual(got[backend], wantPerNode) {
			t.Errorf("%s allocation = %#v, want %#v", backend, got[backend], wantPerNode)
		}
	}
}

func TestDefaultPlanNamesAndAddressesAreUniqueAndMarked(t *testing.T) {
	assets, err := Plan(DefaultSpec())
	if err != nil {
		t.Fatal(err)
	}

	names := make(map[string]bool)
	addresses := make(map[string]bool)
	for _, asset := range assets {
		if !strings.HasPrefix(asset.Name, GeneratedPrefix) {
			t.Errorf("name %q lacks generated prefix", asset.Name)
		}
		if asset.Marker != GeneratedMarker {
			t.Errorf("asset %q marker = %q", asset.Name, asset.Marker)
		}
		if names[asset.Name] {
			t.Fatalf("duplicate name %q", asset.Name)
		}
		if addresses[asset.IP] {
			t.Fatalf("duplicate address %q", asset.IP)
		}
		names[asset.Name] = true
		addresses[asset.IP] = true
	}
}

func TestDefaultPlanIsDeterministic(t *testing.T) {
	first, err := Plan(DefaultSpec())
	if err != nil {
		t.Fatal(err)
	}
	second, err := Plan(DefaultSpec())
	if err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(first)
	b, _ := json.Marshal(second)
	if string(a) != string(b) {
		t.Fatal("identical specs produced different plans")
	}
}

func TestDefaultPlanStaysWithinEachUsableSlash23(t *testing.T) {
	spec := DefaultSpec()
	assets, err := Plan(spec)
	if err != nil {
		t.Fatal(err)
	}

	prefixByBackend := make(map[string]netip.Prefix)
	for _, node := range spec.Nodes {
		prefixByBackend[node.Backend] = netip.MustParsePrefix(node.CIDR)
	}
	for _, asset := range assets {
		prefix := prefixByBackend[asset.Backend]
		address := netip.MustParseAddr(asset.IP)
		if !prefix.Contains(address) {
			t.Fatalf("%s is outside %s for %s", address, prefix, asset.Backend)
		}
		if address == prefix.Addr() {
			t.Fatalf("asset uses network address %s", address)
		}
		broadcast := prefix.Addr()
		for i := 1; i < 1<<(32-prefix.Bits()); i++ {
			broadcast = broadcast.Next()
		}
		if address == broadcast {
			t.Fatalf("asset uses broadcast address %s", address)
		}
	}
}

func TestPlanRejectsNodeAllocationBeyondUsableRange(t *testing.T) {
	spec := DefaultSpec()
	spec.Protocols = []ProtocolSpec{{Name: "ssh", Protocol: "ssh", Port: 22, PerNode: 511}}
	if _, err := Plan(spec); err == nil || !strings.Contains(err.Error(), "usable") {
		t.Fatalf("error = %v, want usable-address error", err)
	}
}

func TestExtensionPlanHasApprovedCountsAndCIDRs(t *testing.T) {
	assets, err := Plan(ExtensionSpec())
	if err != nil {
		t.Fatal(err)
	}
	if len(assets) != 150 {
		t.Fatalf("extension count=%d", len(assets))
	}
	protocols := map[string]int{}
	backends := map[string]int{}
	for _, asset := range assets {
		protocols[asset.Protocol]++
		backends[asset.Backend]++
		if asset.Marker != ExtensionMarker || !strings.HasPrefix(asset.Name, ExtensionPrefix) {
			t.Fatalf("unexpected extension identity: %+v", asset)
		}
	}
	if protocols["rdp"] != 100 || protocols["web"] != 50 {
		t.Fatalf("protocols=%v", protocols)
	}
	want := map[string]int{"10.19.88.145": 38, "10.19.88.146": 38, "10.19.88.147": 37, "10.19.88.149": 37}
	if !reflect.DeepEqual(backends, want) {
		t.Fatalf("backends=%v want=%v", backends, want)
	}
}

func TestCombinedPlanHasUnique2150Assets(t *testing.T) {
	assets, err := CombinedPlan()
	if err != nil {
		t.Fatal(err)
	}
	if len(assets) != 2150 {
		t.Fatalf("combined count=%d", len(assets))
	}
	names, addresses := map[string]bool{}, map[string]bool{}
	for _, asset := range assets {
		if names[asset.Name] || addresses[asset.IP] {
			t.Fatalf("duplicate combined asset %+v", asset)
		}
		names[asset.Name], addresses[asset.IP] = true, true
	}
}

func TestCapacityPlanAddsDedicatedSSHScalePool(t *testing.T) {
	assets, err := CapacityPlan()
	if err != nil {
		t.Fatal(err)
	}
	if len(assets) != 4150 {
		t.Fatalf("capacity count=%d, want 4150", len(assets))
	}
	protocols := map[string]int{}
	newByBackend := map[string]int{}
	names, addresses := map[string]bool{}, map[string]bool{}
	for _, asset := range assets {
		protocols[asset.Protocol]++
		if asset.Marker == SSHScaleMarker {
			newByBackend[asset.Backend]++
			if asset.Protocol != "ssh" || !strings.HasPrefix(asset.Name, SSHScalePrefix) {
				t.Fatalf("unexpected SSH scale asset: %+v", asset)
			}
		}
		if names[asset.Name] || addresses[asset.IP] {
			t.Fatalf("duplicate capacity asset: %+v", asset)
		}
		names[asset.Name], addresses[asset.IP] = true, true
	}
	if protocols["ssh"] != 3000 {
		t.Fatalf("ssh count=%d, want 3000", protocols["ssh"])
	}
	want := map[string]int{"10.19.88.145": 500, "10.19.88.146": 500, "10.19.88.147": 500, "10.19.88.149": 500}
	if !reflect.DeepEqual(newByBackend, want) {
		t.Fatalf("SSH scale backends=%v want=%v", newByBackend, want)
	}
}
