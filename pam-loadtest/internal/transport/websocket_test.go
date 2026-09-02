package transport

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestRunWebSocketContinuouslyExchangesTraffic(t *testing.T) {
	var received atomic.Int64
	var receivedType atomic.Int64
	upgrader := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Auth-Token") != "runtime-token" {
			http.Error(w, "unauthorized", 401)
			return
		}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		for {
			messageType, body, err := conn.ReadMessage()
			if err != nil {
				return
			}
			received.Add(1)
			receivedType.Store(int64(messageType))
			if err := conn.WriteMessage(websocket.BinaryMessage, append([]byte("out:"), body...)); err != nil {
				return
			}
		}
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancel()
	stats, err := RunWebSocket(ctx, WebSocketOptions{
		URL: "ws" + strings.TrimPrefix(srv.URL, "http"), Headers: http.Header{"X-Auth-Token": {"runtime-token"}},
		Interval: 10 * time.Millisecond, MessageType: websocket.TextMessage, Payload: func(sequence uint64) []byte { return []byte("active\n") },
	})
	if err != context.DeadlineExceeded {
		t.Fatalf("err=%v", err)
	}
	if received.Load() < 3 || stats.SentMessages < 3 || stats.ReceivedMessages < 3 {
		t.Fatalf("insufficient activity: %+v server=%d", stats, received.Load())
	}
	if stats.SentBytes == 0 || stats.ReceivedBytes == 0 {
		t.Fatalf("missing byte counters: %+v", stats)
	}
	if receivedType.Load() != websocket.TextMessage {
		t.Fatalf("message type=%d", receivedType.Load())
	}
}

func TestRunWebSocketRejectsUnsafeOptions(t *testing.T) {
	_, err := RunWebSocket(context.Background(), WebSocketOptions{URL: "http://example.test", Interval: time.Second})
	if err == nil {
		t.Fatal("expected invalid websocket URL")
	}
}

func TestRunWebSocketInvokesAfterDialBeforeFirstPayload(t *testing.T) {
	connected := make(chan struct{})
	first := make(chan bool, 1)
	upgrader := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		_, _, err = conn.ReadMessage()
		if err == nil {
			select {
			case <-connected:
				first <- true
			default:
				first <- false
			}
		}
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, _ = RunWebSocket(ctx, WebSocketOptions{URL: "ws" + strings.TrimPrefix(srv.URL, "http"), Interval: 5 * time.Millisecond, Payload: func(uint64) []byte { return []byte("x") }, AfterDial: func() error { close(connected); return nil }})
	if !<-first {
		t.Fatal("payload was sent before AfterDial completed")
	}
}

func TestRunWebSocketSendsStartupPayloadsOnceBeforePeriodicActivity(t *testing.T) {
	received := make(chan string, 3)
	upgrader := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		for count := 0; ; count++ {
			_, body, err := conn.ReadMessage()
			if err != nil {
				return
			}
			if count < cap(received) {
				received <- string(body)
			}
			_ = conn.WriteMessage(websocket.TextMessage, []byte("output"))
		}
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	stats, err := RunWebSocket(ctx, WebSocketOptions{
		URL: "ws" + strings.TrimPrefix(srv.URL, "http"), MessageType: websocket.TextMessage,
		StartupPayloads: [][]byte{[]byte("init-1"), []byte("init-2")}, StartupInterval: time.Millisecond,
		Interval: 5 * time.Millisecond, Payload: func(uint64) []byte { return []byte("heartbeat") },
	})
	if err != context.DeadlineExceeded {
		t.Fatalf("err=%v", err)
	}
	for i, want := range []string{"init-1", "init-2", "heartbeat"} {
		if got := <-received; got != want {
			t.Fatalf("payload %d=%q want=%q", i, got, want)
		}
	}
	if stats.SentMessages < 3 || stats.SentBytes == 0 || stats.ReceivedBytes == 0 {
		t.Fatalf("stats=%+v", stats)
	}
}

func TestRunWebSocketAllowsConnectionOnlyWithoutApplicationPayload(t *testing.T) {
	upgrader := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		<-r.Context().Done()
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Millisecond)
	defer cancel()
	_, err := RunWebSocket(ctx, WebSocketOptions{URL: "ws" + strings.TrimPrefix(srv.URL, "http"), MessageType: websocket.TextMessage, ConnectionOnly: true, InactivityTimeout: time.Second})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err=%v", err)
	}
}

func TestRunWebSocketFailsWhenInboundTrafficIsInactive(t *testing.T) {
	upgrader := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	stats, err := RunWebSocket(ctx, WebSocketOptions{URL: "ws" + strings.TrimPrefix(srv.URL, "http"), Interval: 5 * time.Millisecond, InactivityTimeout: 30 * time.Millisecond, Payload: func(uint64) []byte { return []byte("active") }})
	if err == nil || !strings.Contains(err.Error(), "inbound traffic inactive") || stats.SentMessages == 0 || stats.ReceivedMessages != 0 {
		t.Fatalf("stats=%+v err=%v", stats, err)
	}
}
