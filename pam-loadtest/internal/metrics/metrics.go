package metrics

import (
	"fmt"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

type Metrics struct {
	started      *prometheus.CounterVec
	active       *prometheus.GaugeVec
	connected    *prometheus.CounterVec
	failed       *prometheus.CounterVec
	disconnected *prometheus.CounterVec
	latency      *prometheus.HistogramVec
	bytes        *prometheus.CounterVec
	attempts     atomic.Int64
	failures     atomic.Int64
	disconnects  atomic.Int64
}

func New(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		started:      prometheus.NewCounterVec(prometheus.CounterOpts{Name: "pam_loadtest_sessions_started_total", Help: "Started sessions."}, []string{"protocol", "mode"}),
		active:       prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "pam_loadtest_sessions_active", Help: "Currently active sessions."}, []string{"protocol", "mode"}),
		connected:    prometheus.NewCounterVec(prometheus.CounterOpts{Name: "pam_loadtest_sessions_connected_total", Help: "Connected sessions."}, []string{"protocol", "mode"}),
		failed:       prometheus.NewCounterVec(prometheus.CounterOpts{Name: "pam_loadtest_sessions_failed_total", Help: "Failed sessions."}, []string{"protocol", "mode", "reason"}),
		disconnected: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "pam_loadtest_sessions_disconnected_total", Help: "Disconnected sessions."}, []string{"protocol", "mode", "reason"}),
		latency:      prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "pam_loadtest_connect_latency_seconds", Help: "Connection latency.", Buckets: prometheus.ExponentialBuckets(.05, 2, 12)}, []string{"protocol", "mode"}),
		bytes:        prometheus.NewCounterVec(prometheus.CounterOpts{Name: "pam_loadtest_bytes_total", Help: "Transferred bytes."}, []string{"protocol", "mode", "direction"}),
	}
	reg.MustRegister(m.started, m.active, m.connected, m.failed, m.disconnected, m.latency, m.bytes)
	return m
}

func (m *Metrics) Started(protocol, mode string) {
	m.started.WithLabelValues(protocol, mode).Inc()
	m.attempts.Add(1)
}
func (m *Metrics) Active(protocol, mode string, delta float64) {
	m.active.WithLabelValues(protocol, mode).Add(delta)
}
func (m *Metrics) Connected(protocol, mode string, d time.Duration) {
	m.connected.WithLabelValues(protocol, mode).Inc()
	m.latency.WithLabelValues(protocol, mode).Observe(d.Seconds())
}
func (m *Metrics) Failed(protocol, mode, reason string) {
	m.failed.WithLabelValues(protocol, mode, reason).Inc()
	m.failures.Add(1)
}
func (m *Metrics) Disconnected(protocol, mode, reason string) {
	m.disconnected.WithLabelValues(protocol, mode, reason).Inc()
	m.disconnects.Add(1)
}
func (m *Metrics) Traffic(protocol, mode string, sent, received int64) {
	m.bytes.WithLabelValues(protocol, mode, "sent").Add(float64(sent))
	m.bytes.WithLabelValues(protocol, mode, "received").Add(float64(received))
}
func (m *Metrics) Snapshot() Snapshot {
	return Snapshot{Attempts: m.attempts.Load(), Failures: m.failures.Load(), Disconnects: m.disconnects.Load()}
}

type Snapshot struct{ Attempts, Failures, Disconnects int64 }
type StopPolicy struct {
	MinAttempts                       int64
	MaxFailureRate, MaxDisconnectRate float64
}

func (p StopPolicy) Evaluate(s Snapshot) (bool, string) {
	if s.Attempts < p.MinAttempts || s.Attempts == 0 {
		return false, ""
	}
	if rate := float64(s.Failures) / float64(s.Attempts); rate > p.MaxFailureRate {
		return true, fmt.Sprintf("failure rate %.4f exceeds %.4f", rate, p.MaxFailureRate)
	}
	if rate := float64(s.Disconnects) / float64(s.Attempts); rate > p.MaxDisconnectRate {
		return true, fmt.Sprintf("disconnect rate %.4f exceeds %.4f", rate, p.MaxDisconnectRate)
	}
	return false, ""
}
