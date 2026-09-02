package session

import (
	"context"
	"time"

	"pam-loadtest/internal/config"
)

type Job struct {
	ID        int
	Protocol  config.Protocol
	Mode      config.ExecutionMode
	AssetID   string
	AccountID string
}

type CloseReason string

const (
	Completed CloseReason = "completed"
	Cancelled CloseReason = "cancelled"
	Failed    CloseReason = "failed"
)

type Observation struct {
	Reason             CloseReason
	Mode               config.ExecutionMode
	ConnectLatency     time.Duration
	PrepareLatency     time.Duration
	EditorReadyLatency time.Duration
	SentBytes          int64
	ReceivedBytes      int64
	ActivityEvents     int64
	LastActivity       time.Time
	Err                error
}

type Handle interface {
	Wait(context.Context) Observation
	Close() error
}

type ConnectionAware interface{ Connected() <-chan struct{} }
type ObservationSource interface {
	Observe(context.Context) Observation
}
type OutcomeFinalizer interface{ Finalize(Observation, bool) }
type ConnectRetryReporter interface {
	ConnectRetry()
	ConnectRetrySucceeded()
	ConnectRetryExhausted()
}

type Runner interface {
	Run(context.Context, Job) (Handle, error)
}
