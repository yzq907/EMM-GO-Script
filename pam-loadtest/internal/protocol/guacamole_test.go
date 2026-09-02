package protocol

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestGuacamoleInstructionRoundTripAndFragment(t *testing.T) {
	raw := append(EncodeInstruction("sync", "12345"), EncodeInstruction("name", "桌面")...)
	items, remainder, err := ParseInstructions(raw[:len(raw)-2])
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Opcode != "sync" || string(remainder) == "" {
		t.Fatalf("items=%+v remainder=%q", items, remainder)
	}
	items, remainder, err = ParseInstructions(append(remainder, raw[len(raw)-2:]...))
	if err != nil || len(items) != 1 || items[0].Opcode != "name" || items[0].Args[0] != "桌面" || len(remainder) != 0 {
		t.Fatalf("items=%+v remainder=%q err=%v", items, remainder, err)
	}
}

func TestGuacamoleTunnelUsesObservedQueryAuthentication(t *testing.T) {
	options, err := GuacamoleTunnelOptions("http://pam.test:8088", "session-id", http.Header{"X-Auth-Token": {"runtime-token"}}, 1280, 720, 96, time.Second, 15*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(options.URL)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Query().Get("X-Auth-Token") != "runtime-token" || options.Headers.Get("X-Auth-Token") != "runtime-token" {
		t.Fatal("token must be supplied through the observed query and runtime header")
	}
}

func TestRunGuacamoleSendsActiveInputAndAcknowledgesSync(t *testing.T) {
	var received atomic.Int64
	var keepaliveReceived atomic.Bool
	var syncEchoVerified atomic.Bool
	firstOpcode := make(chan string, 1)
	afterSync := make(chan []string, 1)
	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.WriteMessage(websocket.TextMessage, EncodeInstruction("audio", "1", "audio/L16"))
		_, first, err := conn.ReadMessage()
		if err != nil {
			return
		}
		items, _, err := ParseInstructions(first)
		if err != nil || len(items) != 1 {
			firstOpcode <- "invalid"
			return
		}
		firstOpcode <- items[0].Opcode
		_ = conn.WriteMessage(websocket.TextMessage, EncodeInstruction("sync", "42"))
		opcodes := make([]string, 0, 2)
		for len(opcodes) < 2 {
			_, body, err := conn.ReadMessage()
			if err != nil {
				return
			}
			items, _, err := ParseInstructions(body)
			if err != nil || len(items) == 0 {
				return
			}
			opcodes = append(opcodes, items[0].Opcode)
			received.Add(int64(len(body)))
		}
		afterSync <- opcodes
		_ = conn.WriteMessage(websocket.TextMessage, EncodeInstruction("sync", "42"))
		echoVerified := false
		for attempts := 0; attempts < 10 && !echoVerified; attempts++ {
			_, echo, err := conn.ReadMessage()
			if err != nil {
				return
			}
			echoItems, _, err := ParseInstructions(echo)
			if err != nil {
				return
			}
			for _, item := range echoItems {
				if item.Opcode == "sync" && len(item.Args) == 1 && item.Args[0] == "42" {
					echoVerified = true
				}
			}
			received.Add(int64(len(echo)))
		}
		if !echoVerified {
			return
		}
		syncEchoVerified.Store(true)
		for {
			_, body, err := conn.ReadMessage()
			if err != nil {
				return
			}
			if strings.HasPrefix(string(body), "3.nop,13.") {
				keepaliveReceived.Store(true)
			}
			received.Add(int64(len(body)))
		}
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancel()
	stats, err := RunGuacamole(ctx, GuacamoleOptions{
		URL:               "ws" + strings.TrimPrefix(server.URL, "http"),
		Width:             1280,
		Height:            720,
		DPI:               96,
		ActivityInterval:  10 * time.Millisecond,
		KeepaliveInterval: 10 * time.Millisecond,
		InactivityTimeout: 200 * time.Millisecond,
	})
	if err == nil || ctx.Err() == nil {
		t.Fatalf("err=%v context=%v", err, ctx.Err())
	}
	if stats.ReceivedMessages == 0 || stats.SentMessages < 3 || received.Load() == 0 {
		t.Fatalf("stats=%+v received=%d", stats, received.Load())
	}
	if got := <-firstOpcode; got != "ack" {
		t.Fatalf("first outbound opcode=%q", got)
	}
	if got := <-afterSync; len(got) != 2 || got[0] != "sync" || got[1] != "size" {
		t.Fatalf("post-sync outbound opcodes=%v", got)
	}
	if !syncEchoVerified.Load() {
		t.Fatal("client did not echo the server sync timestamp")
	}
	if !keepaliveReceived.Load() {
		t.Fatal("PAM tunnel keepalive was not sent")
	}
}

func TestRunGuacamoleFailsWhenInboundTrafficStops(t *testing.T) {
	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		<-r.Context().Done()
	}))
	defer server.Close()

	_, err := RunGuacamole(context.Background(), GuacamoleOptions{
		URL:               "ws" + strings.TrimPrefix(server.URL, "http"),
		Width:             1280,
		Height:            720,
		DPI:               96,
		ActivityInterval:  10 * time.Millisecond,
		InactivityTimeout: 30 * time.Millisecond,
	})
	if err == nil || !strings.Contains(err.Error(), "inactive") {
		t.Fatalf("err=%v", err)
	}
}

func TestRunGuacamoleConnectionOnlyDoesNotSendMouseOrKeyboard(t *testing.T) {
	inputs := make(chan string, 4)
	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.WriteMessage(websocket.TextMessage, EncodeInstruction("sync", "42"))
		for {
			_, body, err := conn.ReadMessage()
			if err != nil {
				return
			}
			items, _, err := ParseInstructions(body)
			if err != nil {
				return
			}
			for _, item := range items {
				inputs <- item.Opcode
			}
		}
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Millisecond)
	defer cancel()
	_, _ = RunGuacamole(ctx, GuacamoleOptions{URL: "ws" + strings.TrimPrefix(server.URL, "http"), Width: 1280, Height: 720, DPI: 96, ActivityInterval: time.Millisecond, KeepaliveInterval: 10 * time.Millisecond, InactivityTimeout: time.Second, ConnectionOnly: true})
	close(inputs)
	for opcode := range inputs {
		if opcode == "mouse" || opcode == "key" {
			t.Fatalf("connection-only emitted user input %q", opcode)
		}
	}
}
