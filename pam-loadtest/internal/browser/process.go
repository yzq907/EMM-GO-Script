package browser

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"time"
)

type workerMessage struct {
	Type             string   `json:"type"`
	ID               string   `json:"id,omitempty"`
	Protocol         string   `json:"protocol,omitempty"`
	URL              string   `json:"url,omitempty"`
	AssetID          string   `json:"assetId,omitempty"`
	AccountID        string   `json:"accountId,omitempty"`
	LoginURL         string   `json:"loginUrl,omitempty"`
	Username         string   `json:"username,omitempty"`
	Password         string   `json:"password,omitempty"`
	Cookies          []Cookie `json:"cookies,omitempty"`
	Sequence         int64    `json:"sequence,omitempty"`
	ConnectLatencyMS int64    `json:"connectLatencyMs,omitempty"`
	PrepareMS        int64    `json:"prepareMs,omitempty"`
	EditorReadyMS    int64    `json:"editorReadyMs,omitempty"`
	Error            string   `json:"error,omitempty"`
}

type ProcessClient struct {
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	scanner *bufio.Scanner
	writeMu sync.Mutex
	stateMu sync.Mutex
	pending map[string]chan workerMessage
	closed  bool
}

func NewProcessClient(command string, args ...string) (*ProcessClient, error) {
	cmd := exec.Command(command, args...)
	cmd.Env = append(os.Environ(), "GO_BROWSER_HELPER=1")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start browser worker: %w", err)
	}
	c := &ProcessClient{cmd: cmd, stdin: stdin, scanner: bufio.NewScanner(stdout), pending: make(map[string]chan workerMessage)}
	go c.readLoop()
	return c, nil
}

func (c *ProcessClient) readLoop() {
	for c.scanner.Scan() {
		var message workerMessage
		if err := json.Unmarshal(c.scanner.Bytes(), &message); err != nil {
			c.broadcast(workerMessage{Type: "fatal", Error: err.Error()})
			return
		}
		c.stateMu.Lock()
		ch := c.pending[message.ID]
		if message.ID == "" {
			for _, current := range c.pending {
				select {
				case current <- message:
				default:
				}
			}
		}
		c.stateMu.Unlock()
		if ch != nil {
			select {
			case ch <- message:
			default:
			}
		}
	}
	if err := c.scanner.Err(); err != nil {
		c.broadcast(workerMessage{Type: "fatal", Error: err.Error()})
	} else {
		c.broadcast(workerMessage{Type: "fatal", Error: io.EOF.Error()})
	}
}

func (c *ProcessClient) broadcast(message workerMessage) {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	for _, ch := range c.pending {
		select {
		case ch <- message:
		default:
		}
	}
}

func (c *ProcessClient) send(message workerMessage) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return json.NewEncoder(c.stdin).Encode(message)
}

func (c *ProcessClient) Run(ctx context.Context, job Job) (Result, error) {
	startedAt := time.Now()
	id := strconv.Itoa(job.ID)
	c.stateMu.Lock()
	if c.closed {
		c.stateMu.Unlock()
		return Result{}, fmt.Errorf("browser worker is closed")
	}
	if _, exists := c.pending[id]; exists {
		c.stateMu.Unlock()
		return Result{}, fmt.Errorf("browser job %s already running", id)
	}
	messages := make(chan workerMessage, 16)
	c.pending[id] = messages
	c.stateMu.Unlock()
	defer func() { c.stateMu.Lock(); delete(c.pending, id); c.stateMu.Unlock() }()
	if err := c.send(workerMessage{Type: "start", ID: id, Protocol: job.Protocol, URL: job.URL, AssetID: job.AssetID, AccountID: job.AccountID, LoginURL: job.LoginURL, Username: job.Username, Password: job.Password, Cookies: job.Cookies}); err != nil {
		return Result{}, err
	}
	result := Result{JobID: job.ID}
	var connectedOnce sync.Once
	for {
		select {
		case <-ctx.Done():
			_ = c.send(workerMessage{Type: "stop", ID: id})
			stopTimer := time.NewTimer(5 * time.Second)
			for {
				select {
				case message := <-messages:
					if message.Type == "heartbeat" {
						result.Heartbeats++
						result.LastActivity = time.Now()
					}
					if message.Type == "stopped" {
						stopTimer.Stop()
						return result, ctx.Err()
					}
					if message.Type == "fatal" {
						return result, fmt.Errorf("browser worker: %s", message.Error)
					}
				case <-stopTimer.C:
					return result, fmt.Errorf("browser worker stop timeout: %w", ctx.Err())
				}
			}
		case message := <-messages:
			if message.ID != "" && message.ID != id {
				continue
			}
			switch message.Type {
			case "started":
				if message.PrepareMS > 0 {
					result.PrepareLatency = time.Duration(message.PrepareMS) * time.Millisecond
				}
				if message.EditorReadyMS > 0 {
					result.EditorReadyLatency = time.Duration(message.EditorReadyMS) * time.Millisecond
				}
				connectedOnce.Do(func() {
					if job.OnConnected != nil {
						latency := time.Since(startedAt)
						if message.ConnectLatencyMS > 0 {
							latency = time.Duration(message.ConnectLatencyMS) * time.Millisecond
						}
						job.OnConnected(latency)
					}
				})
			case "heartbeat":
				result.Heartbeats++
				result.LastActivity = time.Now()
			case "error", "fatal":
				return result, fmt.Errorf("browser worker: %s", message.Error)
			case "stopped":
				return result, nil
			}
		}
	}
}

func (c *ProcessClient) Close() error {
	c.stateMu.Lock()
	if c.closed {
		c.stateMu.Unlock()
		return nil
	}
	c.closed = true
	c.stateMu.Unlock()
	_ = c.send(workerMessage{Type: "shutdown"})
	_ = c.stdin.Close()
	if err := c.cmd.Wait(); err != nil {
		return fmt.Errorf("browser worker exit: %w", err)
	}
	return nil
}
