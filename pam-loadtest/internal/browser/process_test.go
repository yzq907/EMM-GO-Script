package browser

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"sync"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	if os.Getenv("GO_BROWSER_HELPER") == "1" {
		helperMain()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestProcessClientExchangesNDJSONAndStopsOnCancellation(t *testing.T) {
	c, err := NewProcessClient(os.Args[0], "-test.run=TestBrowserWorkerHelper", "--")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	connected := make(chan time.Duration, 1)
	result, err := c.Run(ctx, Job{ID: 7, Protocol: "rdp", URL: "http://example.test/session", OnConnected: func(latency time.Duration) { connected <- latency }})
	if err != context.DeadlineExceeded {
		t.Fatalf("err=%v", err)
	}
	if result.JobID != 7 || result.Heartbeats < 1 {
		t.Fatalf("result=%+v", result)
	}
	select {
	case latency := <-connected:
		if latency <= 0 {
			t.Fatalf("connect latency=%s", latency)
		}
	default:
		t.Fatal("started message did not trigger connection callback")
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel2()
	result, err = c.Run(ctx2, Job{ID: 8, Protocol: "web", URL: "http://example.test/web"})
	if err != context.DeadlineExceeded || result.JobID != 8 || result.Heartbeats < 1 {
		t.Fatalf("second run result=%+v err=%v", result, err)
	}
}

func TestProcessClientMultiplexesConcurrentSessions(t *testing.T) {
	c, err := NewProcessClient(os.Args[0], "-test.run=TestBrowserWorkerHelper", "--")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var wg sync.WaitGroup
	results := make(chan Result, 2)
	for _, id := range []int{21, 22} {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			result, _ := c.Run(ctx, Job{ID: id, Protocol: "rdp", URL: "multiplex"})
			results <- result
		}(id)
	}
	wg.Wait()
	close(results)
	seen := map[int]bool{}
	for result := range results {
		if result.Heartbeats > 0 {
			seen[result.JobID] = true
		}
	}
	if !seen[21] || !seen[22] {
		t.Fatalf("both sessions did not receive multiplexed heartbeats: %v", seen)
	}
}

func TestProcessClientPassesRuntimeBrowserCredentials(t *testing.T) {
	c, err := NewProcessClient(os.Args[0], "-test.run=TestBrowserWorkerHelper", "--")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	result, _ := c.Run(ctx, Job{ID: 30, Protocol: "web", URL: "auth", LoginURL: "http://pam.test", Username: "runtime-user", Password: "runtime-pass"})
	if result.Heartbeats < 1 {
		t.Fatalf("credentials were not delivered to worker: %+v", result)
	}
}

func TestProcessClientPassesRuntimeBrowserCookies(t *testing.T) {
	c, err := NewProcessClient(os.Args[0], "-test.run=TestBrowserWorkerHelper", "--")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	result, _ := c.Run(ctx, Job{ID: 31, Protocol: "rdp", URL: "cookie-auth", Cookies: []Cookie{{Name: "sid", Value: "runtime-cookie", URL: "http://pam.test"}}})
	if result.Heartbeats < 1 {
		t.Fatalf("cookies were not delivered to worker: %+v", result)
	}
}

func TestProcessClientPassesAssetAndAccountBinding(t *testing.T) {
	c, err := NewProcessClient(os.Args[0], "-test.run=TestBrowserWorkerHelper", "--")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	result, _ := c.Run(ctx, Job{ID: 32, Protocol: "mysql", URL: "binding", AssetID: "asset-bound", AccountID: "account-bound"})
	if result.Heartbeats < 1 {
		t.Fatalf("asset/account binding was not delivered to worker: %+v", result)
	}
}

func TestProcessClientUsesWorkerMeasuredMySQLTimings(t *testing.T) {
	c, err := NewProcessClient(os.Args[0], "-test.run=TestBrowserWorkerHelper", "--")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	connected := make(chan time.Duration, 1)
	result, err := c.Run(ctx, Job{ID: 33, Protocol: "mysql", URL: "timing", OnConnected: func(latency time.Duration) { connected <- latency }})
	if err != context.DeadlineExceeded {
		t.Fatalf("err=%v", err)
	}
	if result.PrepareLatency != 6789*time.Millisecond || result.EditorReadyLatency != 456*time.Millisecond {
		t.Fatalf("result=%+v", result)
	}
	select {
	case latency := <-connected:
		if latency != 2345*time.Millisecond {
			t.Fatalf("connect latency=%s", latency)
		}
	default:
		t.Fatal("worker measured timing did not trigger connection callback")
	}
}

func TestBrowserWorkerHelper(t *testing.T) {
	if os.Getenv("GO_BROWSER_HELPER") != "1" {
		return
	}
	helperMain()
}

func helperMain() {
	scanner := bufio.NewScanner(os.Stdin)
	encoder := json.NewEncoder(os.Stdout)
	var multiplex []any
	for scanner.Scan() {
		var message map[string]any
		_ = json.Unmarshal(scanner.Bytes(), &message)
		switch message["type"] {
		case "start":
			started := map[string]any{"type": "started", "id": message["id"]}
			if message["url"] == "timing" {
				started["connectLatencyMs"] = 2345
				started["prepareMs"] = 6789
				started["editorReadyMs"] = 456
			}
			_ = encoder.Encode(started)
			if message["url"] == "binding" {
				if message["assetId"] == "asset-bound" && message["accountId"] == "account-bound" {
					_ = encoder.Encode(map[string]any{"type": "heartbeat", "id": message["id"], "sequence": 1})
				}
				continue
			}
			if message["url"] == "auth" {
				if message["username"] == "runtime-user" && message["password"] == "runtime-pass" {
					_ = encoder.Encode(map[string]any{"type": "heartbeat", "id": message["id"], "sequence": 1})
				}
			}
			if message["url"] == "cookie-auth" {
				cookies, _ := message["cookies"].([]any)
				if len(cookies) == 1 {
					cookie, _ := cookies[0].(map[string]any)
					if cookie["name"] == "sid" && cookie["value"] == "runtime-cookie" && cookie["url"] == "http://pam.test" {
						_ = encoder.Encode(map[string]any{"type": "heartbeat", "id": message["id"], "sequence": 1})
					}
				}
			}
			if message["url"] == "multiplex" {
				multiplex = append(multiplex, message["id"])
				if len(multiplex) == 2 {
					for _, id := range multiplex {
						_ = encoder.Encode(map[string]any{"type": "heartbeat", "id": id, "sequence": 1})
					}
				}
			} else {
				_ = encoder.Encode(map[string]any{"type": "heartbeat", "id": message["id"], "sequence": 1})
			}
		case "stop":
			_ = encoder.Encode(map[string]any{"type": "stopped", "id": message["id"]})
		case "shutdown":
			os.Exit(0)
		}
	}
}
