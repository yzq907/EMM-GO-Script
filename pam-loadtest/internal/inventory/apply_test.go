package inventory

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

type fakeInventoryAPI struct {
	assets      []RemoteAsset
	batchSizes  []int
	failOnBatch int
}

func (f *fakeInventoryAPI) ListAssets(context.Context) ([]RemoteAsset, error) {
	return append([]RemoteAsset(nil), f.assets...), nil
}

func (f *fakeInventoryAPI) ImportAssets(_ context.Context, batch []Asset, _ ImportCredentials) error {
	f.batchSizes = append(f.batchSizes, len(batch))
	if f.failOnBatch > 0 && len(f.batchSizes) == f.failOnBatch {
		return fmt.Errorf("batch failed")
	}
	for _, asset := range batch {
		f.assets = append(f.assets, RemoteAsset{ID: "asset-" + asset.Name, Name: asset.Name, Description: asset.Marker, IP: asset.IP, Protocol: asset.Protocol, DBType: asset.DBType, Port: asset.Port, AccountCount: 1, DefaultAccountID: "account-" + asset.Name})
	}
	return nil
}

func TestApplyDefaultsToDryRunAndResumesExactRecords(t *testing.T) {
	desired := []Asset{
		{Name: GeneratedPrefix + "one", Marker: GeneratedMarker, IP: "10.200.0.1", Protocol: "ssh", Port: 22},
		{Name: GeneratedPrefix + "two", Marker: GeneratedMarker, IP: "10.200.0.2", Protocol: "ssh", Port: 22},
	}
	api := &fakeInventoryAPI{assets: []RemoteAsset{{ID: "asset-one", Name: desired[0].Name, Description: GeneratedMarker, IP: desired[0].IP, Protocol: "ssh", Port: 22, AccountCount: 1, DefaultAccountID: "account-one"}}}
	report, err := Apply(context.Background(), api, desired, ApplyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if report.Existing != 1 || report.Pending != 1 || report.Created != 0 || len(api.batchSizes) != 0 {
		t.Fatalf("report=%+v batches=%v", report, api.batchSizes)
	}
}

func TestApplyRejectsNameOrAddressConflictsBeforeWriting(t *testing.T) {
	desired := []Asset{{Name: GeneratedPrefix + "one", Marker: GeneratedMarker, IP: "10.200.0.1", Protocol: "ssh", Port: 22}}
	tests := []RemoteAsset{
		{Name: desired[0].Name, Description: "not-our-marker", IP: desired[0].IP, Protocol: "ssh", Port: 22},
		{Name: "existing-production", IP: desired[0].IP, Protocol: "ssh", Port: 22},
	}
	for _, existing := range tests {
		api := &fakeInventoryAPI{assets: []RemoteAsset{existing}}
		_, err := Apply(context.Background(), api, desired, ApplyOptions{Execute: true})
		if err == nil || !strings.Contains(err.Error(), "conflict") {
			t.Errorf("existing=%+v error=%v", existing, err)
		}
		if len(api.batchSizes) != 0 {
			t.Fatalf("wrote after conflict: %v", api.batchSizes)
		}
	}
}

func TestApplyUsesBoundedBatchesAndStopsOnFailure(t *testing.T) {
	desired := make([]Asset, 120)
	for i := range desired {
		desired[i] = Asset{Name: fmt.Sprintf("%s%03d", GeneratedPrefix, i), Marker: GeneratedMarker, IP: fmt.Sprintf("10.200.0.%d", i+1), Protocol: "ssh", Port: 22}
	}
	api := &fakeInventoryAPI{failOnBatch: 3}
	report, err := Apply(context.Background(), api, desired, ApplyOptions{Execute: true, BatchSize: 80})
	if err == nil {
		t.Fatal("expected batch failure")
	}
	if got := fmt.Sprint(api.batchSizes); got != "[50 50 20]" {
		t.Fatalf("batch sizes = %s", got)
	}
	if report.Created != 100 {
		t.Fatalf("created = %d, want 100", report.Created)
	}
}

func TestApplyLimitCreatesOnlyRequestedCanary(t *testing.T) {
	desired := []Asset{
		{Name: GeneratedPrefix + "one", Marker: GeneratedMarker, IP: "10.200.0.1", Protocol: "ssh", Port: 22},
		{Name: GeneratedPrefix + "two", Marker: GeneratedMarker, IP: "10.200.0.2", Protocol: "ssh", Port: 22},
	}
	api := &fakeInventoryAPI{}
	report, err := Apply(context.Background(), api, desired, ApplyOptions{Execute: true, Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if report.Created != 1 || fmt.Sprint(api.batchSizes) != "[1]" {
		t.Fatalf("report=%+v batches=%v", report, api.batchSizes)
	}
}

func TestApplyLimitCapsDesiredPrefixIncludingExistingCanary(t *testing.T) {
	desired := []Asset{
		{Name: GeneratedPrefix + "one", Marker: GeneratedMarker, IP: "10.200.0.1", Protocol: "ssh", Port: 22},
		{Name: GeneratedPrefix + "two", Marker: GeneratedMarker, IP: "10.200.0.2", Protocol: "ssh", Port: 22},
	}
	api := &fakeInventoryAPI{assets: []RemoteAsset{{ID: "asset-one", Name: desired[0].Name, Description: desired[0].Marker, IP: desired[0].IP, Protocol: "ssh", Port: 22, AccountCount: 1, DefaultAccountID: "account-one"}}}
	report, err := Apply(context.Background(), api, desired, ApplyOptions{Execute: true, Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if report.Desired != 1 || report.Existing != 1 || report.Created != 0 || len(api.batchSizes) != 0 {
		t.Fatalf("report=%+v batches=%v", report, api.batchSizes)
	}
}

func TestReconcileAcceptsPAMDashForEmptyDatabaseType(t *testing.T) {
	desired := Asset{Name: GeneratedPrefix + "one", Marker: GeneratedMarker, IP: "10.200.0.1", Protocol: "ssh", Port: 22}
	remote := RemoteAsset{ID: "asset-one", Name: desired.Name, Description: desired.Marker, IP: desired.IP, Protocol: desired.Protocol, DBType: "-", Port: desired.Port, AccountCount: 1, DefaultAccountID: "account-one"}
	missing, exact, err := reconcile([]Asset{desired}, []RemoteAsset{remote})
	if err != nil || exact != 1 || len(missing) != 0 {
		t.Fatalf("missing=%v exact=%d err=%v", missing, exact, err)
	}
}
