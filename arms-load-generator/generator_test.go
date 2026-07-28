package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestGeneratorSendsCompleteTransactions(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	var mu sync.Mutex
	received := make([]parsedFrame, 0, 8)
	serverDone := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverDone <- acceptErr
			return
		}
		defer connection.Close()
		reader := bufio.NewReader(connection)
		for range 8 {
			frame, readErr := readFrame(reader)
			if readErr != nil {
				serverDone <- readErr
				return
			}
			mu.Lock()
			received = append(received, frame)
			mu.Unlock()
		}
		serverDone <- nil
	}()

	config, err := LoadConfig(writeConfig(t, validConfigJSON))
	if err != nil {
		t.Fatal(err)
	}
	config.Host = listener.Addr().String()
	config.Threads = 1
	config.Duration = 250 * time.Millisecond
	config.TargetTPS = 20
	config.RampUp = 0
	config.HeartbeatInterval = time.Second
	config.StatsInterval = 50 * time.Millisecond
	config.ResultsFile = filepath.Join(t.TempDir(), "results.csv")

	result, err := NewGenerator(config).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.Final.SuccessfulTransactions < 2 {
		t.Fatalf("successful transactions = %d", result.Final.SuccessfulTransactions)
	}
	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("fixture did not receive two transactions")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(received) != 8 {
		t.Fatalf("received frames = %d", len(received))
	}
	for transaction := 0; transaction < 2; transaction++ {
		base := transaction * 4
		if received[base].messageType != 0x01 || received[base+1].subtype != 0x02 || received[base+2].subtype != 0x03 || received[base+3].subtype != 0x63 {
			t.Fatalf("bad transaction frame order: %+v", received[base:base+4])
		}
		if received[base].requestID != received[base+1].requestID || received[base].requestID != received[base+2].requestID || received[base].requestID != received[base+3].requestID {
			t.Fatal("transaction frames do not share request ID")
		}
	}
}

func TestWorkerReconnectsWithoutReplayingFailedTransaction(t *testing.T) {
	config, err := LoadConfig(writeConfig(t, validConfigJSON))
	if err != nil {
		t.Fatal(err)
	}
	config.ConnectTimeout = 100 * time.Millisecond
	config.WriteTimeout = 100 * time.Millisecond
	config.HeartbeatInterval = time.Second

	var dialCount int
	var dialMu sync.Mutex
	dial := func(context.Context, string, string) (net.Conn, error) {
		dialMu.Lock()
		dialCount++
		current := dialCount
		dialMu.Unlock()
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			reader := bufio.NewReader(server)
			framesToRead := 4
			if current > 1 {
				framesToRead = 8
			}
			for range framesToRead {
				if _, readErr := readFrame(reader); readErr != nil {
					return
				}
			}
		}()
		return client, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 600*time.Millisecond)
	defer cancel()
	permits := make(chan struct{}, 4)
	startup := make(chan bool, 1)
	stats := &Stats{}
	for range 3 {
		permits <- struct{}{}
	}
	runWorker(ctx, 1, config, permits, startup, stats, dial)
	if stats.Reconnects.Load() < 1 {
		t.Fatalf("reconnects = %d", stats.Reconnects.Load())
	}
	if stats.SuccessfulTransactions.Load()+stats.FailedTransactions.Load() != 3 {
		t.Fatalf("transaction accounting mismatch: success=%d failed=%d",
			stats.SuccessfulTransactions.Load(), stats.FailedTransactions.Load())
	}
}

func readFrame(reader io.Reader) (parsedFrame, error) {
	header := make([]byte, FrameHeaderSize)
	if _, err := io.ReadFull(reader, header); err != nil {
		return parsedFrame{}, err
	}
	bodyLength := binary.BigEndian.Uint64(header[52:60])
	body := make([]byte, int(bodyLength))
	if _, err := io.ReadFull(reader, body); err != nil {
		return parsedFrame{}, err
	}
	return parsedFrame{
		messageType: header[6], subtype: header[7],
		sequence:  binary.BigEndian.Uint64(header[8:16]),
		requestID: string(header[16:52]), body: body,
	}, nil
}
