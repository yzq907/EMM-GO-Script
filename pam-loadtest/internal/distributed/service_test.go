package distributed

import (
	"context"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc/test/bufconn"
	"pam-loadtest/internal/runreport"
)

func TestGRPCAgentRequiresTokenAndAcceptsJobs(t *testing.T) {
	listener := bufconn.Listen(1 << 20)
	received := make(chan RunRequest, 1)
	registry := NewRegistry(25, func(_ context.Context, r RunRequest) (runreport.Report, error) {
		received <- r
		return completedReport(r.RunID), nil
	})
	capabilities := Capabilities{Version: "test-version", Capacity: 25, DirectCapacity: 25, BrowserCapacity: 8, DirectProtocols: []string{"ssh", "rdp", "vnc", "web", "mysql"}}
	server := NewAgentServerWithCapabilities("runtime-agent-token", capabilities, registry)
	go server.Serve(listener)
	defer server.Stop()
	dial := func(ctx context.Context, _ string) (net.Conn, error) { return listener.DialContext(ctx) }
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	client, err := DialAgent(ctx, "bufnet", dial, "runtime-agent-token")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	health, err := client.Health(ctx)
	if err != nil || health.Capabilities.Version != "test-version" || health.Capabilities.BrowserCapacity != 8 {
		t.Fatalf("health=%+v err=%v", health, err)
	}
	req := RunRequest{RunID: "run-1", RampNanos: int64(time.Minute), HoldNanos: int64(2 * time.Minute), SSHActivityIntervalNanos: int64(5 * time.Second), ContinueOnErrors: true, Seed: 42, Jobs: []WireJob{{ID: 1, Protocol: "ssh", Mode: "direct", AssetID: "a-1", AccountID: "u-1"}}}
	if _, err := client.Start(ctx, req); err != nil {
		t.Fatal(err)
	}
	if got := <-received; got.RunID != "run-1" || len(got.Jobs) != 1 || got.RampNanos != int64(time.Minute) || got.SSHActivityIntervalNanos != int64(5*time.Second) || !got.ContinueOnErrors || got.Seed != 42 {
		t.Fatalf("got=%+v", got)
	}
	deadline := time.Now().Add(time.Second)
	for {
		status, err := client.Status(ctx, StatusRequest{RunID: "run-1"})
		if err != nil {
			t.Fatal(err)
		}
		if status.Status == Completed {
			if status.Report == nil || status.Report.Totals.Planned != 1 {
				t.Fatalf("status=%+v", status)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("agent did not complete")
		}
		time.Sleep(time.Millisecond)
	}

	bad, err := DialAgent(ctx, "bufnet", dial, "wrong-token")
	if err != nil {
		t.Fatal(err)
	}
	defer bad.Close()
	if _, err := bad.Health(ctx); err == nil {
		t.Fatal("expected unauthenticated call")
	}
}
