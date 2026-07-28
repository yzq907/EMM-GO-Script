package main

import (
	"encoding/csv"
	"fmt"
	"strconv"
	"sync/atomic"
	"time"
)

type ErrorKind int

const (
	ErrorConnect ErrorKind = iota
	ErrorTimeout
	ErrorShortWrite
	ErrorIO
)

type Stats struct {
	SuccessfulTransactions atomic.Int64
	FailedTransactions     atomic.Int64
	Frames                 atomic.Int64
	Bytes                  atomic.Int64
	ActiveConnections      atomic.Int64
	ConnectionAttempts     atomic.Int64
	Reconnects             atomic.Int64
	SchedulerBacklog       atomic.Int64
	ScheduledTPS           atomic.Int64
	ConnectErrors          atomic.Int64
	TimeoutErrors          atomic.Int64
	ShortWriteErrors       atomic.Int64
	IOErrors               atomic.Int64
	Heartbeats             atomic.Int64
}

type StatsSnapshot struct {
	SuccessfulTransactions int64
	FailedTransactions     int64
	Frames                 int64
	Bytes                  int64
	ActiveConnections      int64
	ConnectionAttempts     int64
	Reconnects             int64
	SchedulerBacklog       int64
	ScheduledTPS           int64
	ConnectErrors          int64
	TimeoutErrors          int64
	ShortWriteErrors       int64
	IOErrors               int64
	Heartbeats             int64
}

type IntervalRecord struct {
	Elapsed      time.Duration
	ScheduledTPS int
	ActualTPS    float64
	Snapshot     StatsSnapshot
}

func (stats *Stats) RecordSuccess(bytes, frames int) {
	stats.SuccessfulTransactions.Add(1)
	stats.Frames.Add(int64(frames))
	stats.Bytes.Add(int64(bytes))
}

func (stats *Stats) RecordHeartbeat(bytes int) {
	stats.Heartbeats.Add(1)
	stats.Frames.Add(1)
	stats.Bytes.Add(int64(bytes))
}

func (stats *Stats) RecordFailure(kind ErrorKind) {
	stats.FailedTransactions.Add(1)
	switch kind {
	case ErrorConnect:
		stats.ConnectErrors.Add(1)
	case ErrorTimeout:
		stats.TimeoutErrors.Add(1)
	case ErrorShortWrite:
		stats.ShortWriteErrors.Add(1)
	default:
		stats.IOErrors.Add(1)
	}
}

func (stats *Stats) RecordConnectionError() {
	stats.ConnectErrors.Add(1)
}

func (stats *Stats) RecordTransportError(kind ErrorKind) {
	switch kind {
	case ErrorTimeout:
		stats.TimeoutErrors.Add(1)
	case ErrorShortWrite:
		stats.ShortWriteErrors.Add(1)
	default:
		stats.IOErrors.Add(1)
	}
}

func (stats *Stats) Snapshot() StatsSnapshot {
	return StatsSnapshot{
		SuccessfulTransactions: stats.SuccessfulTransactions.Load(),
		FailedTransactions:     stats.FailedTransactions.Load(),
		Frames:                 stats.Frames.Load(), Bytes: stats.Bytes.Load(),
		ActiveConnections:  stats.ActiveConnections.Load(),
		ConnectionAttempts: stats.ConnectionAttempts.Load(), Reconnects: stats.Reconnects.Load(),
		SchedulerBacklog: stats.SchedulerBacklog.Load(), ScheduledTPS: stats.ScheduledTPS.Load(),
		ConnectErrors: stats.ConnectErrors.Load(), TimeoutErrors: stats.TimeoutErrors.Load(),
		ShortWriteErrors: stats.ShortWriteErrors.Load(), IOErrors: stats.IOErrors.Load(),
		Heartbeats: stats.Heartbeats.Load(),
	}
}

func writeCSVHeader(writer *csv.Writer) error {
	return writer.Write([]string{
		"elapsed_seconds", "scheduled_tps", "actual_tps", "successful_transactions",
		"failed_transactions", "frames", "bytes", "active_connections",
		"connection_attempts", "reconnects", "scheduler_backlog", "heartbeats",
		"connect_errors", "timeout_errors", "short_write_errors", "io_errors",
	})
}

func writeCSVRow(writer *csv.Writer, record IntervalRecord) error {
	snapshot := record.Snapshot
	return writer.Write([]string{
		strconv.FormatFloat(record.Elapsed.Seconds(), 'f', 3, 64),
		strconv.Itoa(record.ScheduledTPS),
		strconv.FormatFloat(record.ActualTPS, 'f', 3, 64),
		strconv.FormatInt(snapshot.SuccessfulTransactions, 10),
		strconv.FormatInt(snapshot.FailedTransactions, 10),
		strconv.FormatInt(snapshot.Frames, 10), strconv.FormatInt(snapshot.Bytes, 10),
		strconv.FormatInt(snapshot.ActiveConnections, 10),
		strconv.FormatInt(snapshot.ConnectionAttempts, 10), strconv.FormatInt(snapshot.Reconnects, 10),
		strconv.FormatInt(snapshot.SchedulerBacklog, 10), strconv.FormatInt(snapshot.Heartbeats, 10),
		strconv.FormatInt(snapshot.ConnectErrors, 10), strconv.FormatInt(snapshot.TimeoutErrors, 10),
		strconv.FormatInt(snapshot.ShortWriteErrors, 10), strconv.FormatInt(snapshot.IOErrors, 10),
	})
}

func formatIntervalLine(record IntervalRecord) string {
	snapshot := record.Snapshot
	return fmt.Sprintf(
		"elapsed=%s target_tps=%d actual_tps=%.1f transactions=%d frames=%d errors=%d reconnects=%d connections=%d bytes=%d backlog=%d",
		record.Elapsed.Round(time.Second), record.ScheduledTPS, record.ActualTPS,
		snapshot.SuccessfulTransactions, snapshot.Frames, snapshot.FailedTransactions,
		snapshot.Reconnects, snapshot.ActiveConnections, snapshot.Bytes, snapshot.SchedulerBacklog,
	)
}
