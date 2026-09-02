package metrics

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func TestRegistryTracksPerProtocolLifecycleAndTraffic(t *testing.T) {
	r := prometheus.NewRegistry()
	m := New(r)
	m.Started("ssh", "direct")
	m.Active("ssh", "direct", 1)
	m.Connected("ssh", "direct", 125*time.Millisecond)
	m.Traffic("ssh", "direct", 10, 20)
	m.Failed("ssh", "direct", "handshake")
	m.Disconnected("ssh", "direct", "abnormal")
	m.Active("ssh", "direct", -1)
	families, err := r.Gather()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"pam_loadtest_sessions_started_total": false, "pam_loadtest_sessions_active": false, "pam_loadtest_connect_latency_seconds": false, "pam_loadtest_bytes_total": false, "pam_loadtest_sessions_failed_total": false, "pam_loadtest_sessions_disconnected_total": false}
	for _, family := range families {
		if _, ok := want[family.GetName()]; ok {
			want[family.GetName()] = true
		}
	}
	for name, found := range want {
		if !found {
			t.Fatalf("metric %s missing", name)
		}
	}
	foundMode := false
	for _, family := range families {
		for _, metric := range family.Metric {
			for _, label := range metric.Label {
				if label.GetName() == "mode" && label.GetValue() == "direct" {
					foundMode = true
				}
			}
		}
	}
	if !foundMode {
		t.Fatal("mode label missing")
	}
}

func TestStopPolicyUsesRatesOnlyAfterMinimumSamples(t *testing.T) {
	p := StopPolicy{MinAttempts: 100, MaxFailureRate: .01, MaxDisconnectRate: .01}
	if stop, _ := p.Evaluate(Snapshot{Attempts: 20, Failures: 20}); stop {
		t.Fatal("must not stop before minimum samples")
	}
	if stop, _ := p.Evaluate(Snapshot{Attempts: 100, Failures: 2}); !stop {
		t.Fatal("expected failure-rate stop")
	}
	if stop, _ := p.Evaluate(Snapshot{Attempts: 100, Disconnects: 2}); !stop {
		t.Fatal("expected disconnect-rate stop")
	}
}
