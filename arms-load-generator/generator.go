package main

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

type dialContextFunc func(context.Context, string, string) (net.Conn, error)

type Generator struct {
	config Config
	stats  *Stats
	dial   dialContextFunc
}

type RunResult struct {
	Started time.Time
	Ended   time.Time
	PeakTPS float64
	Final   StatsSnapshot
}

type reporterResult struct {
	peakTPS float64
	err     error
}

func NewGenerator(config Config) *Generator {
	dialer := &net.Dialer{Timeout: config.ConnectTimeout, KeepAlive: 30 * time.Second}
	return &Generator{
		config: config,
		stats:  &Stats{},
		dial:   dialer.DialContext,
	}
}

func (generator *Generator) Run(parent context.Context) (RunResult, error) {
	resultsFile, err := os.Create(generator.config.ResultsFile)
	if err != nil {
		return RunResult{}, fmt.Errorf("create results file %q: %w", generator.config.ResultsFile, err)
	}
	defer resultsFile.Close()
	csvWriter := csv.NewWriter(resultsFile)
	if err := writeCSVHeader(csvWriter); err != nil {
		return RunResult{}, fmt.Errorf("write CSV header: %w", err)
	}
	csvWriter.Flush()
	if err := csvWriter.Error(); err != nil {
		return RunResult{}, fmt.Errorf("flush CSV header: %w", err)
	}

	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	permitBuffer := generator.config.TargetTPS
	if minimum := generator.config.Threads * 4; permitBuffer < minimum {
		permitBuffer = minimum
	}
	if permitBuffer < 1 {
		permitBuffer = 1
	}
	permits := make(chan struct{}, permitBuffer)
	startup := make(chan bool, generator.config.Threads)

	var workers sync.WaitGroup
	for workerID := 1; workerID <= generator.config.Threads; workerID++ {
		workers.Add(1)
		go func(id int) {
			defer workers.Done()
			runWorker(ctx, id, generator.config, permits, startup, generator.stats, generator.dial)
		}(workerID)
	}

	connected := 0
	for range generator.config.Threads {
		select {
		case success := <-startup:
			if success {
				connected++
			}
		case <-parent.Done():
			cancel()
			workers.Wait()
			return RunResult{}, parent.Err()
		}
	}
	if connected == 0 {
		cancel()
		workers.Wait()
		return RunResult{}, fmt.Errorf("all %d initial ARMS connections failed", generator.config.Threads)
	}

	started := time.Now()
	var scheduler sync.WaitGroup
	if generator.config.TargetTPS > 0 {
		scheduler.Add(1)
		go func() {
			defer scheduler.Done()
			runScheduler(ctx, generator.config.TargetTPS, generator.config.RampUp, schedulerInterval, permits, generator.stats)
		}()
	}

	reporterDone := make(chan reporterResult, 1)
	go runReporter(ctx, started, generator.config, generator.stats, csvWriter, reporterDone)

	timer := time.NewTimer(generator.config.Duration)
	select {
	case <-parent.Done():
		if !timer.Stop() {
			<-timer.C
		}
	case <-timer.C:
	}
	cancel()
	scheduler.Wait()
	workers.Wait()
	report := <-reporterDone
	ended := time.Now()
	result := RunResult{
		Started: started, Ended: ended, PeakTPS: report.peakTPS,
		Final: generator.stats.Snapshot(),
	}
	if report.err != nil {
		return result, report.err
	}
	return result, nil
}

func runWorker(ctx context.Context, workerID int, config Config, permits <-chan struct{}, startup chan<- bool, stats *Stats, dial dialContextFunc) {
	firstAttempt := true
	hadConnection := false
	backoff := 100 * time.Millisecond
	for {
		if ctx.Err() != nil {
			return
		}
		stats.ConnectionAttempts.Add(1)
		connection, err := dial(ctx, "tcp", config.Host)
		if firstAttempt {
			startup <- err == nil
			firstAttempt = false
		}
		if err != nil {
			stats.RecordConnectionError()
			if !waitForReconnect(ctx, backoff) {
				return
			}
			backoff = nextBackoff(backoff)
			continue
		}
		if hadConnection {
			stats.Reconnects.Add(1)
		}
		hadConnection = true
		backoff = 100 * time.Millisecond
		stats.ActiveConnections.Add(1)
		_ = connection.SetWriteDeadline(time.Time{})
		err = serveConnection(ctx, connection, workerID, config, permits, stats)
		stats.ActiveConnections.Add(-1)
		_ = connection.Close()
		if ctx.Err() != nil {
			return
		}
		if err != nil && !waitForReconnect(ctx, backoff) {
			return
		}
	}
}

func serveConnection(ctx context.Context, connection net.Conn, workerID int, config Config, permits <-chan struct{}, stats *Stats) error {
	sequence := uint64(1)
	if config.TargetTPS == 0 {
		for {
			select {
			case <-ctx.Done():
				return nil
			default:
			}
			if err := sendTransaction(connection, workerID, config, &sequence, stats); err != nil {
				return err
			}
		}
	}

	heartbeat := time.NewTimer(config.HeartbeatInterval)
	defer heartbeat.Stop()
	for {
		if ctx.Err() != nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return nil
		case <-heartbeat.C:
			if ctx.Err() != nil {
				return nil
			}
			payload := EncodeHeartbeat()
			if err := writePayload(connection, payload, config.WriteTimeout); err != nil {
				stats.RecordTransportError(classifyWriteError(err))
				return err
			}
			stats.RecordHeartbeat(len(payload))
			heartbeat.Reset(config.HeartbeatInterval)
		case <-permits:
			if ctx.Err() != nil {
				return nil
			}
			if err := sendTransaction(connection, workerID, config, &sequence, stats); err != nil {
				return err
			}
			if !heartbeat.Stop() {
				select {
				case <-heartbeat.C:
				default:
				}
			}
			heartbeat.Reset(config.HeartbeatInterval)
		}
	}
}

func sendTransaction(connection net.Conn, workerID int, config Config, sequence *uint64, stats *Stats) error {
	payload, nextSequence, _, frameCount, err := BuildTransaction(config, *sequence, workerID)
	if err != nil {
		stats.RecordFailure(ErrorIO)
		return err
	}
	*sequence = nextSequence
	if err := writePayload(connection, payload, config.WriteTimeout); err != nil {
		stats.RecordFailure(classifyWriteError(err))
		return err
	}
	stats.RecordSuccess(len(payload), frameCount)
	return nil
}

func writePayload(connection net.Conn, payload []byte, timeout time.Duration) error {
	if err := connection.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	written := 0
	for written < len(payload) {
		count, err := connection.Write(payload[written:])
		written += count
		if err != nil {
			return err
		}
		if count == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func classifyWriteError(err error) ErrorKind {
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		return ErrorTimeout
	}
	if errors.Is(err, io.ErrShortWrite) {
		return ErrorShortWrite
	}
	return ErrorIO
}

func waitForReconnect(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func nextBackoff(current time.Duration) time.Duration {
	current *= 2
	if current > 2*time.Second {
		return 2 * time.Second
	}
	return current
}

func runReporter(ctx context.Context, started time.Time, config Config, stats *Stats, writer *csv.Writer, done chan<- reporterResult) {
	ticker := time.NewTicker(config.StatsInterval)
	defer ticker.Stop()
	previousTime := started
	previousSuccess := int64(0)
	peakTPS := 0.0
	writeRecord := func(now time.Time) error {
		snapshot := stats.Snapshot()
		interval := now.Sub(previousTime)
		if interval <= 0 {
			return nil
		}
		actualTPS := float64(snapshot.SuccessfulTransactions-previousSuccess) / interval.Seconds()
		if actualTPS > peakTPS {
			peakTPS = actualTPS
		}
		record := IntervalRecord{
			Elapsed: now.Sub(started), ScheduledTPS: int(snapshot.ScheduledTPS),
			ActualTPS: actualTPS, Snapshot: snapshot,
		}
		fmt.Println(formatIntervalLine(record))
		if err := writeCSVRow(writer, record); err != nil {
			return err
		}
		writer.Flush()
		if err := writer.Error(); err != nil {
			return err
		}
		previousTime = now
		previousSuccess = snapshot.SuccessfulTransactions
		return nil
	}
	for {
		select {
		case <-ctx.Done():
			err := writeRecord(time.Now())
			done <- reporterResult{peakTPS: peakTPS, err: err}
			return
		case now := <-ticker.C:
			if err := writeRecord(now); err != nil {
				done <- reporterResult{peakTPS: peakTPS, err: fmt.Errorf("write statistics: %w", err)}
				return
			}
		}
	}
}
