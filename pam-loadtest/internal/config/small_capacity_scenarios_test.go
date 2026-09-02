package config

import (
	"path/filepath"
	"testing"
	"time"
)

func TestSmallCapacityScenarioFiles(t *testing.T) {
	type expected struct {
		total     int
		ramp      time.Duration
		protocols map[Protocol]int
		modes     map[Protocol]ModeCounts
	}
	cases := map[string]expected{
		"ssh-200-small.yaml": {
			total: 200, ramp: 200 * time.Second,
			protocols: map[Protocol]int{SSH: 200},
			modes:     map[Protocol]ModeCounts{SSH: {Direct: 200}},
		},
		"graphics-16-small.yaml": {
			total: 16, ramp: 60 * time.Second,
			protocols: map[Protocol]int{RDP: 8, VNC: 2, Web: 4, MySQL: 2},
			modes: map[Protocol]ModeCounts{RDP: {Browser: 8}, VNC: {Browser: 2}, Web: {Browser: 4}, MySQL: {Browser: 2}},
		},
		"graphics-12-small.yaml": {
			total: 12, ramp: 120 * time.Second,
			protocols: map[Protocol]int{RDP: 6, VNC: 2, Web: 3, MySQL: 1},
			modes: map[Protocol]ModeCounts{RDP: {Browser: 6}, VNC: {Browser: 2}, Web: {Browser: 3}, MySQL: {Direct: 1}},
		},
		"graphics-8-small.yaml": {
			total: 8, ramp: 80 * time.Second,
			protocols: map[Protocol]int{RDP: 4, VNC: 1, Web: 2, MySQL: 1},
			modes: map[Protocol]ModeCounts{RDP: {Browser: 4}, VNC: {Browser: 1}, Web: {Browser: 2}, MySQL: {Direct: 1}},
		},
		"graphics-4-small.yaml": {
			total: 4, ramp: 40 * time.Second,
			protocols: map[Protocol]int{RDP: 1, VNC: 1, Web: 1, MySQL: 1},
			modes: map[Protocol]ModeCounts{RDP: {Browser: 1}, VNC: {Browser: 1}, Web: {Browser: 1}, MySQL: {Direct: 1}},
		},
		"mixed-40-small.yaml": {
			total: 40, ramp: 200 * time.Second,
			protocols: map[Protocol]int{SSH: 24, RDP: 8, VNC: 2, Web: 4, MySQL: 2},
			modes: map[Protocol]ModeCounts{SSH: {Direct: 24}, RDP: {Browser: 8}, VNC: {Browser: 2}, Web: {Browser: 4}, MySQL: {Direct: 2}},
		},
		"mixed-116-observation.yaml": {
			total: 116, ramp: 3 * time.Minute,
			protocols: map[Protocol]int{SSH: 100, RDP: 8, VNC: 2, Web: 4, MySQL: 2},
			modes: map[Protocol]ModeCounts{SSH: {Direct: 100}, RDP: {Browser: 8}, VNC: {Browser: 2}, Web: {Browser: 4}, MySQL: {Browser: 2}},
		},
		"mixed-30-small.yaml": {
			total: 30, ramp: 150 * time.Second,
			protocols: map[Protocol]int{SSH: 18, RDP: 6, VNC: 2, Web: 3, MySQL: 1},
			modes: map[Protocol]ModeCounts{SSH: {Direct: 18}, RDP: {Browser: 6}, VNC: {Browser: 2}, Web: {Browser: 3}, MySQL: {Direct: 1}},
		},
		"mixed-20-small.yaml": {
			total: 20, ramp: 100 * time.Second,
			protocols: map[Protocol]int{SSH: 12, RDP: 4, VNC: 1, Web: 2, MySQL: 1},
			modes: map[Protocol]ModeCounts{SSH: {Direct: 12}, RDP: {Browser: 4}, VNC: {Browser: 1}, Web: {Browser: 2}, MySQL: {Direct: 1}},
		},
	}

	for name, want := range cases {
		t.Run(name, func(t *testing.T) {
			cfg, err := Load(filepath.Join("..", "..", "configs", name))
			if err != nil {
				t.Fatal(err)
			}
			if cfg.Total != want.total || cfg.Ramp != want.ramp || cfg.Hold != 10*time.Minute || !cfg.ContinueOnErrors {
				t.Fatalf("runtime policy total=%d ramp=%s hold=%s continue=%v", cfg.Total, cfg.Ramp, cfg.Hold, cfg.ContinueOnErrors)
			}
			jobs, err := cfg.Expand()
			if err != nil {
				t.Fatal(err)
			}
			protocols := map[Protocol]int{}
			modes := map[Protocol]ModeCounts{}
			for _, job := range jobs {
				protocols[job.Protocol]++
				count := modes[job.Protocol]
				if job.Mode == Browser {
					count.Browser++
				} else {
					count.Direct++
				}
				modes[job.Protocol] = count
			}
			for protocol, count := range want.protocols {
				if protocols[protocol] != count || modes[protocol] != want.modes[protocol] {
					t.Fatalf("%s protocol=%d mode=%+v", protocol, protocols[protocol], modes[protocol])
				}
				mapping := cfg.Assets[protocol]
				if mapping.AssetIDEnv == "" || mapping.AccountIDEnv == "" {
					t.Fatalf("%s asset mapping missing", protocol)
				}
			}
			if cfg.Protocols[SSH] > 0 && cfg.SSHActivityInterval != 5*time.Second {
				t.Fatalf("SSH activity interval=%s", cfg.SSHActivityInterval)
			}
		})
	}
}

func TestGraphics24RetryScenarioFile(t *testing.T) {
	cfg, err := Load(filepath.Join("..", "..", "configs", "graphics-24-retry.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Total != 24 || cfg.ConnectRetries != 3 {
		t.Fatalf("total=%d retries=%d", cfg.Total, cfg.ConnectRetries)
	}
	jobs, err := cfg.Expand()
	if err != nil {
		t.Fatal(err)
	}
	want := map[Protocol]int{RDP: 12, VNC: 3, Web: 6, MySQL: 3}
	got := map[Protocol]int{}
	for _, job := range jobs {
		got[job.Protocol]++
		if job.Mode != Browser {
			t.Fatalf("job mode=%s", job.Mode)
		}
	}
	for protocol, count := range want {
		if got[protocol] != count {
			t.Fatalf("%s=%d want %d", protocol, got[protocol], count)
		}
	}
}
