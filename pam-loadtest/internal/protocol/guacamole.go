package protocol

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/gorilla/websocket"
	"pam-loadtest/internal/transport"
)

const maxGuacamoleElement = 16 << 20

type Instruction struct {
	Opcode string
	Args   []string
}

func EncodeInstruction(opcode string, args ...string) []byte {
	values := append([]string{opcode}, args...)
	result := make([]byte, 0, 64)
	for index, value := range values {
		result = strconv.AppendInt(result, int64(utf8.RuneCountInString(value)), 10)
		result = append(result, '.')
		result = append(result, value...)
		if index == len(values)-1 {
			result = append(result, ';')
		} else {
			result = append(result, ',')
		}
	}
	return result
}

func ParseInstructions(input []byte) ([]Instruction, []byte, error) {
	items := make([]Instruction, 0)
	position := 0
	for position < len(input) {
		start := position
		values := make([]string, 0, 4)
		for {
			dot := position
			for dot < len(input) && input[dot] >= '0' && input[dot] <= '9' {
				dot++
			}
			if dot == position {
				return nil, nil, fmt.Errorf("invalid guacamole element length")
			}
			if dot == len(input) {
				return items, append([]byte(nil), input[start:]...), nil
			}
			if input[dot] != '.' {
				return nil, nil, fmt.Errorf("invalid guacamole element delimiter")
			}
			length, err := strconv.Atoi(string(input[position:dot]))
			if err != nil || length < 0 || length > maxGuacamoleElement {
				return nil, nil, fmt.Errorf("invalid guacamole element length")
			}
			valueStart := dot + 1
			valueEnd, complete := runeByteEnd(input, valueStart, length)
			if !complete || valueEnd >= len(input) {
				return items, append([]byte(nil), input[start:]...), nil
			}
			values = append(values, string(input[valueStart:valueEnd]))
			separator := input[valueEnd]
			position = valueEnd + 1
			if separator == ';' {
				if len(values) == 0 || values[0] == "" {
					return nil, nil, fmt.Errorf("guacamole opcode is empty")
				}
				items = append(items, Instruction{Opcode: values[0], Args: append([]string(nil), values[1:]...)})
				break
			}
			if separator != ',' {
				return nil, nil, fmt.Errorf("invalid guacamole instruction delimiter")
			}
		}
	}
	return items, nil, nil
}

func runeByteEnd(input []byte, start, count int) (int, bool) {
	position := start
	for index := 0; index < count; index++ {
		if position >= len(input) {
			return 0, false
		}
		_, size := utf8.DecodeRune(input[position:])
		if size == 0 || (size == 1 && input[position] >= utf8.RuneSelf) {
			return 0, false
		}
		position += size
	}
	return position, true
}

type GuacamoleOptions struct {
	URL               string
	Headers           http.Header
	Width             int
	Height            int
	DPI               int
	ActivityInterval  time.Duration
	KeepaliveInterval time.Duration
	InactivityTimeout time.Duration
	DialTimeout       time.Duration
	WriteTimeout      time.Duration
	AfterDial         func() error
	// ConnectionOnly suppresses generated mouse and keyboard input. Protocol
	// acknowledgements, display negotiation, and keepalives remain enabled.
	ConnectionOnly bool
}

func GuacamoleTunnelOptions(baseURL, sessionID string, headers http.Header, width, height, dpi int, activity, inactivity time.Duration) (GuacamoleOptions, error) {
	u, err := websocketBase(baseURL)
	if err != nil {
		return GuacamoleOptions{}, err
	}
	u.Path = "/sessions/" + sessionID + "/tunnel"
	query := url.Values{"width": {strconv.Itoa(width)}, "height": {strconv.Itoa(height)}, "dpi": {strconv.Itoa(dpi)}}
	if token := headers.Get("X-Auth-Token"); token != "" {
		query.Set("X-Auth-Token", token)
	}
	u.RawQuery = query.Encode()
	return GuacamoleOptions{URL: u.String(), Headers: headers, Width: width, Height: height, DPI: dpi, ActivityInterval: activity, InactivityTimeout: inactivity}, nil
}

func RunGuacamole(ctx context.Context, options GuacamoleOptions) (transport.Stats, error) {
	u, err := url.Parse(options.URL)
	if err != nil || (u.Scheme != "ws" && u.Scheme != "wss") || u.Host == "" {
		return transport.Stats{}, fmt.Errorf("invalid guacamole websocket URL")
	}
	if options.Width <= 0 || options.Height <= 0 || options.DPI <= 0 {
		return transport.Stats{}, fmt.Errorf("invalid guacamole display dimensions")
	}
	if options.ActivityInterval <= 0 {
		options.ActivityInterval = time.Second
	}
	if options.InactivityTimeout <= 0 {
		options.InactivityTimeout = 15 * time.Second
	}
	if options.KeepaliveInterval <= 0 {
		options.KeepaliveInterval = 15 * time.Second
	}
	if options.DialTimeout <= 0 {
		options.DialTimeout = 15 * time.Second
	}
	if options.WriteTimeout <= 0 {
		options.WriteTimeout = 5 * time.Second
	}
	conn, response, err := (&websocket.Dialer{HandshakeTimeout: options.DialTimeout}).DialContext(ctx, options.URL, options.Headers)
	if err != nil {
		if response != nil {
			return transport.Stats{}, fmt.Errorf("guacamole handshake returned %d", response.StatusCode)
		}
		return transport.Stats{}, fmt.Errorf("guacamole handshake failed: %w", err)
	}
	defer conn.Close()
	if options.AfterDial != nil {
		if err := options.AfterDial(); err != nil {
			return transport.Stats{}, fmt.Errorf("guacamole post-handshake action failed: %w", err)
		}
	}

	var sentMessages, receivedMessages, sentBytes, receivedBytes atomic.Int64
	var lastReceived atomic.Int64
	var lastActivity atomic.Int64
	var ready atomic.Bool
	var sizeSent atomic.Bool
	lastReceived.Store(time.Now().UnixNano())
	var writeMu sync.Mutex
	write := func(body []byte) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		_ = conn.SetWriteDeadline(time.Now().Add(options.WriteTimeout))
		if err := conn.WriteMessage(websocket.TextMessage, body); err != nil {
			return err
		}
		sentMessages.Add(1)
		sentBytes.Add(int64(len(body)))
		lastActivity.Store(time.Now().UnixNano())
		return nil
	}
	snapshot := func() transport.Stats {
		stats := transport.Stats{SentMessages: sentMessages.Load(), ReceivedMessages: receivedMessages.Load(), SentBytes: sentBytes.Load(), ReceivedBytes: receivedBytes.Load()}
		if value := lastActivity.Load(); value > 0 {
			stats.LastActivity = time.Unix(0, value)
		}
		return stats
	}
	readErr := make(chan error, 1)
	go func() {
		var remainder []byte
		for {
			_, body, err := conn.ReadMessage()
			if err != nil {
				readErr <- err
				return
			}
			receivedMessages.Add(1)
			receivedBytes.Add(int64(len(body)))
			lastReceived.Store(time.Now().UnixNano())
			lastActivity.Store(time.Now().UnixNano())
			combined := append(remainder, body...)
			items, rest, err := ParseInstructions(combined)
			if err != nil {
				readErr <- err
				return
			}
			remainder = rest
			for _, item := range items {
				switch {
				case (item.Opcode == "audio" || item.Opcode == "blob") && len(item.Args) >= 1:
					if err := write(EncodeInstruction("ack", item.Args[0], "OK", "0")); err != nil {
						readErr <- err
						return
					}
				case item.Opcode == "sync" && len(item.Args) == 1:
					// guacd rejects a client sync whose timestamp is newer than
					// the last sync it sent (user-handlers.c __guac_handle_sync),
					// so acknowledge by echoing the server's own timestamp as
					// the Guacamole JavaScript client does. A client-clock
					// epoch-millisecond value is always in the future and makes
					// guacd abort the connection with "User connection aborted".
					if err := write(EncodeInstruction("sync", item.Args[0])); err != nil {
						readErr <- err
						return
					}
					if sizeSent.CompareAndSwap(false, true) {
						if err := write(EncodeInstruction("size", strconv.Itoa(options.Width), strconv.Itoa(options.Height), strconv.Itoa(options.DPI))); err != nil {
							readErr <- err
							return
						}
					}
					ready.Store(true)
				}
			}
		}
	}()

	var activity <-chan time.Time
	var activityTicker *time.Ticker
	if !options.ConnectionOnly {
		activityTicker = time.NewTicker(options.ActivityInterval)
		defer activityTicker.Stop()
		activity = activityTicker.C
	}
	keepalive := time.NewTicker(options.KeepaliveInterval)
	defer keepalive.Stop()
	livenessInterval := options.InactivityTimeout / 2
	if livenessInterval < time.Millisecond {
		livenessInterval = time.Millisecond
	}
	liveness := time.NewTicker(livenessInterval)
	defer liveness.Stop()
	sequence := 0
	for {
		select {
		case <-ctx.Done():
			writeMu.Lock()
			_ = conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(options.WriteTimeout))
			writeMu.Unlock()
			return snapshot(), ctx.Err()
		case err := <-readErr:
			if ctx.Err() != nil {
				return snapshot(), ctx.Err()
			}
			return snapshot(), fmt.Errorf("guacamole read failed: %w", err)
		case <-liveness.C:
			if time.Since(time.Unix(0, lastReceived.Load())) >= options.InactivityTimeout {
				return snapshot(), fmt.Errorf("guacamole inbound traffic inactive for %s", options.InactivityTimeout)
			}
		case <-activity:
			if !ready.Load() {
				continue
			}
			sequence++
			var body []byte
			if sequence%2 == 0 {
				body = EncodeInstruction("mouse", strconv.Itoa(80+sequence%500), strconv.Itoa(80+(sequence*7)%300), "0")
			} else {
				body = append(EncodeInstruction("key", "65361", "1"), EncodeInstruction("key", "65361", "0")...)
			}
			if err := write(body); err != nil {
				return snapshot(), fmt.Errorf("guacamole activity failed: %w", err)
			}
		case <-keepalive.C:
			body := EncodeInstruction("nop", strconv.FormatInt(time.Now().UnixMilli(), 10))
			if err := write(body); err != nil {
				return snapshot(), fmt.Errorf("guacamole keepalive failed: %w", err)
			}
		}
	}
}
