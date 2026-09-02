package distributed

import (
	"context"
	"errors"
	"testing"
	"time"

	"pam-loadtest/internal/config"
	"pam-loadtest/internal/runreport"
)

func boundRequest(runID string) RunRequest {
	return RunRequest{RunID: runID, RampNanos: int64(time.Minute), HoldNanos: int64(time.Minute), SSHActivityIntervalNanos: int64(time.Second), Jobs: []WireJob{{ID: 1, Protocol: "ssh", Mode: "direct", AssetID: "a-1", AccountID: "u-1"}}}
}

func TestRegistryRejectsInvalidSSHActivityInterval(t *testing.T) {
	registry := NewRegistry(1, func(context.Context, RunRequest) (runreport.Report, error) {
		return runreport.Report{}, nil
	})
	for _, interval := range []time.Duration{0, 500 * time.Millisecond, 1500 * time.Millisecond, 61 * time.Second} {
		request := boundRequest("invalid-interval")
		request.SSHActivityIntervalNanos = int64(interval)
		if _, err := registry.Start(context.Background(), request); err == nil {
			t.Fatalf("expected interval %s to be rejected", interval)
		}
	}
}

func TestRegistryRejectsInvalidSSHActivityMode(t *testing.T) {
	registry := NewRegistry(1, func(context.Context, RunRequest) (runreport.Report, error) {
		return runreport.Report{}, nil
	})
	request := boundRequest("invalid-activity-mode")
	request.SSHActivityMode = "invalid"
	if _, err := registry.Start(context.Background(), request); err == nil {
		t.Fatal("expected invalid SSH activity mode to be rejected")
	}
}

func TestRegistryRejectsInvalidGraphicalActivityInterval(t *testing.T) {
	registry := NewRegistry(1, func(context.Context, RunRequest) (runreport.Report, error) {
		return runreport.Report{}, nil
	})
	for _, intervals := range []map[string]int64{
		{"ssh": int64(time.Second)},
		{"rdp": int64(500 * time.Millisecond)},
		{"vnc": int64(61 * time.Second)},
	} {
		request := boundRequest("invalid-graphical-interval")
		request.GraphicalActivityIntervalNanos = intervals
		if _, err := registry.Start(context.Background(), request); err == nil {
			t.Fatalf("expected intervals %v to be rejected", intervals)
		}
	}
}

func completedReport(runID string) runreport.Report {
	return runreport.Report{RunID: runID, Status: string(Completed), Totals: runreport.Counts{Planned: 1, Used: 1, Started: 1}, Protocols: map[config.Protocol]runreport.Counts{config.SSH: {Planned: 1, Used: 1, Started: 1}}}
}

func TestRegistryLifecycleCompletesWithReport(t *testing.T) {
	release := make(chan struct{})
	registry := NewRegistry(2, func(ctx context.Context, request RunRequest) (runreport.Report, error) {
		select {
		case <-release:
			return completedReport(request.RunID), nil
		case <-ctx.Done():
			return runreport.Report{}, ctx.Err()
		}
	})
	response, err := registry.Start(context.Background(), boundRequest("run-1"))
	if err != nil || response.Accepted != 1 || response.RunID != "run-1" {
		t.Fatalf("response=%+v err=%v", response, err)
	}
	status, err := registry.Status(context.Background(), StatusRequest{RunID: "run-1"})
	if err != nil || status.Status != Running {
		t.Fatalf("status=%+v err=%v", status, err)
	}
	close(release)
	deadline := time.Now().Add(time.Second)
	for status.Status != Completed && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
		status, err = registry.Status(context.Background(), StatusRequest{RunID: "run-1"})
		if err != nil {
			t.Fatal(err)
		}
	}
	if status.Status != Completed || status.Report == nil || status.Report.Totals.Used != 1 {
		t.Fatalf("status=%+v", status)
	}
}

func TestRegistryCancelAndValidation(t *testing.T) {
	started := make(chan struct{})
	cancelSeen := make(chan struct{})
	releaseCleanup := make(chan struct{})
	registry := NewRegistry(1, func(ctx context.Context, request RunRequest) (runreport.Report, error) {
		started <- struct{}{}
		<-ctx.Done()
		cancelSeen <- struct{}{}
		<-releaseCleanup
		return runreport.Report{}, ctx.Err()
	})
	if _, err := registry.Start(context.Background(), boundRequest("run-cancel")); err != nil {
		t.Fatal(err)
	}
	<-started
	response, err := registry.Cancel(context.Background(), CancelRequest{RunID: "run-cancel"})
	if err != nil || response.Status != Cancelled {
		t.Fatalf("response=%+v err=%v", response, err)
	}
	<-cancelSeen
	if _, err := registry.Start(context.Background(), boundRequest("next")); err == nil {
		t.Fatal("new run started before cancelled run finished cleanup")
	}
	close(releaseCleanup)
	if _, err := registry.Status(context.Background(), StatusRequest{RunID: "missing"}); err == nil {
		t.Fatal("expected unknown run error")
	}
	invalid := boundRequest("invalid")
	invalid.Jobs[0].AssetID = ""
	if _, err := registry.Start(context.Background(), invalid); err == nil {
		t.Fatal("expected missing binding error")
	}
	over := boundRequest("over")
	over.Jobs = append(over.Jobs, WireJob{ID: 2, Protocol: "ssh", Mode: "direct", AssetID: "a-2", AccountID: "u-2"})
	if _, err := registry.Start(context.Background(), over); err == nil {
		t.Fatal("expected capacity error")
	}
}

func TestRegistryDoesNotExposeCancelledBeforeTerminalReport(t *testing.T) {
	releaseCleanup := make(chan struct{})
	registry := NewRegistry(1, func(ctx context.Context, request RunRequest) (runreport.Report, error) {
		<-ctx.Done()
		<-releaseCleanup
		report := completedReport(request.RunID)
		return report, ctx.Err()
	})
	if _, err := registry.Start(context.Background(), boundRequest("run-cancel-report")); err != nil {
		t.Fatal(err)
	}
	response, err := registry.Cancel(context.Background(), CancelRequest{RunID: "run-cancel-report"})
	if err != nil || response.Status != Cancelled {
		t.Fatalf("response=%+v err=%v", response, err)
	}
	status, err := registry.Status(context.Background(), StatusRequest{RunID: "run-cancel-report"})
	if err != nil || status.Status != Running || status.Report != nil {
		t.Fatalf("cancel cleanup was exposed as terminal: status=%+v err=%v", status, err)
	}
	close(releaseCleanup)
	deadline := time.Now().Add(time.Second)
	for status.Status == Running && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
		status, err = registry.Status(context.Background(), StatusRequest{RunID: "run-cancel-report"})
		if err != nil {
			t.Fatal(err)
		}
	}
	if status.Status != Cancelled || status.Report == nil || status.Report.Status != string(Cancelled) {
		t.Fatalf("cancelled terminal report was not retained: %+v", status)
	}
}

func TestRegistryRejectsModeCapacityOverflow(t *testing.T) {
	registry := NewRegistryWithCapabilities(Capabilities{Version: "v", Capacity: 2, DirectCapacity: 2, BrowserCapacity: 0}, func(context.Context, RunRequest) (runreport.Report, error) {
		return runreport.Report{}, nil
	})
	request := boundRequest("browser-overflow")
	request.Jobs[0].Protocol = "rdp"
	request.Jobs[0].Mode = "browser"
	if _, err := registry.Start(context.Background(), request); err == nil {
		t.Fatal("expected browser capacity rejection")
	}
}

func TestValidateRunRequestAcceptsMySQLBrowser(t *testing.T) {
	request := boundRequest("mysql-browser")
	request.Jobs[0].Protocol = "mysql"
	request.Jobs[0].Mode = "browser"
	capabilities := Capabilities{
		Version:         "v",
		Capacity:        1,
		DirectCapacity:  1,
		BrowserCapacity: 1,
		DirectProtocols: []string{"ssh", "rdp", "vnc", "web", "mysql"},
	}
	if err := validateRunRequest(request, capabilities); err != nil {
		t.Fatalf("mysql browser request rejected: %v", err)
	}
}

func TestRegistryRejectsDuplicateRunAndSanitizesFailure(t *testing.T) {
	release := make(chan struct{})
	registry := NewRegistry(2, func(_ context.Context, request RunRequest) (runreport.Report, error) {
		<-release
		report := completedReport(request.RunID)
		report.Totals.RuntimeFailures = 1
		return report, errors.New("runtime failed for asset secret-asset-id")
	})
	request := boundRequest("same")
	if _, err := registry.Start(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Start(context.Background(), request); err == nil {
		t.Fatal("expected duplicate run error")
	}
	close(release)
	status := StatusResponse{Status: Running}
	deadline := time.Now().Add(time.Second)
	for status.Status == Running && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
		status, _ = registry.Status(context.Background(), StatusRequest{RunID: "same"})
	}
	if status.Status != Failed || status.Report == nil || status.Report.Status != string(Failed) || status.Report.Totals.RuntimeFailures != 1 {
		t.Fatalf("failed report was not retained: %+v", status)
	}
	if status.Error != "run execution failed" {
		t.Fatalf("unsafe failure text: %q", status.Error)
	}
}
