package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"strconv"
	"testing"
	"time"
)

func TestPermitsForTickCarriesFraction(t *testing.T) {
	carry := 0.0
	total := 0
	for range 100 {
		count, nextCarry := permitsForTick(55, time.Second, 0, 10*time.Millisecond, carry)
		total += count
		carry = nextCarry
	}
	if total != 55 {
		t.Fatalf("permits in one second = %d, want 55", total)
	}
}

func TestCurrentTargetTPSRamp(t *testing.T) {
	tests := []struct {
		elapsed time.Duration
		want    int
	}{
		{elapsed: 0, want: 0},
		{elapsed: 2 * time.Second, want: 2000},
		{elapsed: 5 * time.Second, want: 5000},
		{elapsed: 10 * time.Second, want: 10000},
		{elapsed: 20 * time.Second, want: 10000},
	}
	for _, test := range tests {
		if got := currentTargetTPS(10000, test.elapsed, 10*time.Second); got != test.want {
			t.Fatalf("target at %s = %d, want %d", test.elapsed, got, test.want)
		}
	}
}

func TestSchedulerStopsWithContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	permits := make(chan struct{}, 100)
	stats := &Stats{}
	done := make(chan struct{})
	go func() {
		runScheduler(ctx, 1000, 0, time.Millisecond, permits, stats)
		close(done)
	}()
	time.Sleep(10 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("scheduler did not stop after cancellation")
	}
}

func TestStatsSnapshotAndCSV(t *testing.T) {
	stats := &Stats{}
	stats.RecordSuccess(900, 4)
	stats.RecordFailure(ErrorTimeout)
	stats.ConnectionAttempts.Add(2)
	stats.ActiveConnections.Add(1)
	stats.Reconnects.Add(1)
	snapshot := stats.Snapshot()
	if snapshot.SuccessfulTransactions != 1 || snapshot.FailedTransactions != 1 || snapshot.Frames != 4 || snapshot.Bytes != 900 {
		t.Fatalf("unexpected snapshot: %+v", snapshot)
	}

	var output bytes.Buffer
	reporter := csv.NewWriter(&output)
	if err := writeCSVHeader(reporter); err != nil {
		t.Fatal(err)
	}
	if err := writeCSVRow(reporter, IntervalRecord{Elapsed: time.Second, ScheduledTPS: 100, ActualTPS: 99.5, Snapshot: snapshot}); err != nil {
		t.Fatal(err)
	}
	reporter.Flush()
	rows, err := csv.NewReader(bytes.NewReader(output.Bytes())).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0][0] != "elapsed_seconds" || rows[1][1] != strconv.Itoa(100) {
		t.Fatalf("unexpected CSV rows: %#v", rows)
	}
}
