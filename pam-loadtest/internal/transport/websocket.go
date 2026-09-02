package transport

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

type WebSocketOptions struct {
	URL               string
	Headers           http.Header
	Interval          time.Duration
	Payload           func(sequence uint64) []byte
	StartupPayloads   [][]byte
	StartupInterval   time.Duration
	MessageType       int
	AfterDial         func() error
	DialTimeout       time.Duration
	WriteTimeout      time.Duration
	InactivityTimeout time.Duration
	// ConnectionOnly keeps the socket open without emitting application data.
	ConnectionOnly bool
}

type Stats struct {
	SentMessages, ReceivedMessages, SentBytes, ReceivedBytes int64
	LastActivity                                             time.Time
	PrepareLatency, EditorReadyLatency                       time.Duration
}

func RunWebSocket(ctx context.Context, opts WebSocketOptions) (Stats, error) {
	u, err := url.Parse(opts.URL)
	if err != nil || (u.Scheme != "ws" && u.Scheme != "wss") || u.Host == "" {
		return Stats{}, fmt.Errorf("invalid websocket URL")
	}
	if !opts.ConnectionOnly && (opts.Interval <= 0 || opts.Payload == nil) {
		return Stats{}, fmt.Errorf("activity interval and payload are required")
	}
	if opts.DialTimeout == 0 {
		opts.DialTimeout = 15 * time.Second
	}
	if opts.WriteTimeout == 0 {
		opts.WriteTimeout = 5 * time.Second
	}
	if opts.MessageType == 0 {
		opts.MessageType = websocket.BinaryMessage
	}
	if opts.MessageType != websocket.BinaryMessage && opts.MessageType != websocket.TextMessage {
		return Stats{}, fmt.Errorf("websocket message type must be text or binary")
	}
	if opts.InactivityTimeout == 0 {
		opts.InactivityTimeout = 15 * time.Second
	}
	dialer := websocket.Dialer{HandshakeTimeout: opts.DialTimeout}
	conn, resp, err := dialer.DialContext(ctx, opts.URL, opts.Headers)
	if err != nil {
		if resp != nil {
			return Stats{}, fmt.Errorf("websocket handshake returned %d", resp.StatusCode)
		}
		return Stats{}, fmt.Errorf("websocket handshake failed: %w", err)
	}
	defer conn.Close()
	if opts.AfterDial != nil {
		if err := opts.AfterDial(); err != nil {
			return Stats{}, fmt.Errorf("websocket post-handshake action failed: %w", err)
		}
	}
	var sentMessages, receivedMessages, sentBytes, receivedBytes, lastActivity, lastReceived atomic.Int64
	lastReceived.Store(time.Now().UnixNano())
	snapshot := func() Stats {
		stats := Stats{SentMessages: sentMessages.Load(), ReceivedMessages: receivedMessages.Load(), SentBytes: sentBytes.Load(), ReceivedBytes: receivedBytes.Load()}
		if value := lastActivity.Load(); value > 0 {
			stats.LastActivity = time.Unix(0, value)
		}
		return stats
	}
	readErr := make(chan error, 1)
	go func() {
		for {
			_, body, err := conn.ReadMessage()
			if err != nil {
				readErr <- err
				return
			}
			now := time.Now().UnixNano()
			receivedMessages.Add(1)
			receivedBytes.Add(int64(len(body)))
			lastActivity.Store(now)
			lastReceived.Store(now)
		}
	}()
	write := func(body []byte) error {
		_ = conn.SetWriteDeadline(time.Now().Add(opts.WriteTimeout))
		if err := conn.WriteMessage(opts.MessageType, body); err != nil {
			return err
		}
		sentMessages.Add(1)
		sentBytes.Add(int64(len(body)))
		lastActivity.Store(time.Now().UnixNano())
		return nil
	}
	for index, body := range opts.StartupPayloads {
		if index > 0 && opts.StartupInterval > 0 {
			select {
			case <-ctx.Done():
				return snapshot(), ctx.Err()
			case <-time.After(opts.StartupInterval):
			}
		}
		if err := write(body); err != nil {
			return snapshot(), fmt.Errorf("websocket startup write failed: %w", err)
		}
	}
	var activity <-chan time.Time
	var ticker *time.Ticker
	if !opts.ConnectionOnly {
		ticker = time.NewTicker(opts.Interval)
		defer ticker.Stop()
		activity = ticker.C
	}
	livenessInterval := opts.InactivityTimeout / 2
	if livenessInterval < time.Millisecond {
		livenessInterval = time.Millisecond
	}
	liveness := time.NewTicker(livenessInterval)
	defer liveness.Stop()
	sequence := uint64(0)
	for {
		select {
		case <-ctx.Done():
			_ = conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(opts.WriteTimeout))
			return snapshot(), ctx.Err()
		case err := <-readErr:
			if ctx.Err() != nil {
				return snapshot(), ctx.Err()
			}
			return snapshot(), fmt.Errorf("websocket read failed: %w", err)
		case <-liveness.C:
			if opts.ConnectionOnly {
				continue
			}
			if time.Since(time.Unix(0, lastReceived.Load())) >= opts.InactivityTimeout {
				return snapshot(), fmt.Errorf("websocket inbound traffic inactive for %s", opts.InactivityTimeout)
			}
		case <-activity:
			sequence++
			body := opts.Payload(sequence)
			if err := write(body); err != nil {
				return snapshot(), fmt.Errorf("websocket write failed: %w", err)
			}
		}
	}
}
