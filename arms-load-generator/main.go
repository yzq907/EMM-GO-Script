package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	if len(os.Args) != 1 {
		log.Fatalf("this program reads %s and accepts no command-line load parameters", defaultConfigPath)
	}
	config, err := LoadConfig(defaultConfigPath)
	if err != nil {
		log.Fatal(err)
	}
	printEffectiveConfig(config)
	if config.HighThreadWarning() {
		log.Printf("WARNING: threads=%d exceeds the recommended stable limit of %d", config.Threads, highThreadWarning)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	result, err := NewGenerator(config).Run(ctx)
	if err != nil {
		log.Fatal(err)
	}
	printFinalReport(result)
}

func printEffectiveConfig(config Config) {
	mode := fmt.Sprintf("target_tps=%d", config.TargetTPS)
	if config.TargetTPS == 0 {
		mode = "target_tps=unlimited"
	}
	log.Printf(
		"starting ARMS load generator: host=%s threads=%d duration=%s %s ramp_up=%s results=%s",
		config.Host, config.Threads, config.Duration, mode, config.RampUp, config.ResultsFile,
	)
}

func printFinalReport(result RunResult) {
	elapsed := result.Ended.Sub(result.Started)
	if elapsed <= 0 {
		elapsed = time.Nanosecond
	}
	total := result.Final.SuccessfulTransactions + result.Final.FailedTransactions
	successRate := 100.0
	if total > 0 {
		successRate = float64(result.Final.SuccessfulTransactions) * 100 / float64(total)
	}
	averageTPS := float64(result.Final.SuccessfulTransactions) / elapsed.Seconds()
	fmt.Println("========== ARMS load test summary ==========")
	fmt.Printf("duration: %s\n", elapsed.Round(time.Millisecond))
	fmt.Printf("successful_transactions: %d\n", result.Final.SuccessfulTransactions)
	fmt.Printf("failed_transactions: %d\n", result.Final.FailedTransactions)
	fmt.Printf("success_rate: %.4f%%\n", successRate)
	fmt.Printf("average_tps: %.2f\n", averageTPS)
	fmt.Printf("peak_interval_tps: %.2f\n", result.PeakTPS)
	fmt.Printf("frames: %d\n", result.Final.Frames)
	fmt.Printf("heartbeats: %d\n", result.Final.Heartbeats)
	fmt.Printf("bytes: %d\n", result.Final.Bytes)
	fmt.Printf("connection_attempts: %d\n", result.Final.ConnectionAttempts)
	fmt.Printf("reconnects: %d\n", result.Final.Reconnects)
	fmt.Printf("scheduler_backlog: %d\n", result.Final.SchedulerBacklog)
	fmt.Printf("connect_errors: %d\n", result.Final.ConnectErrors)
	fmt.Printf("timeout_errors: %d\n", result.Final.TimeoutErrors)
	fmt.Printf("short_write_errors: %d\n", result.Final.ShortWriteErrors)
	fmt.Printf("io_errors: %d\n", result.Final.IOErrors)
}
