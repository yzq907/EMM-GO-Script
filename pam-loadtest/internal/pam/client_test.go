package pam

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestLoginReusesRuntimeTokenAndCreatesNativeSession(t *testing.T) {
	var sawAuth bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/login":
			w.Header().Set("X-Auth-Token", "runtime-secret")
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: "cookie-secret"})
			_ = json.NewEncoder(w).Encode(map[string]string{"token": "runtime-secret"})
		case strings.HasSuffix(r.URL.Path, "/accounts"):
			sawAuth = r.Header.Get("X-Auth-Token") == "runtime-secret"
			_ = json.NewEncoder(w).Encode([]map[string]string{{"id": "account-1"}})
		case r.URL.Path == "/sessions":
			if r.URL.Query().Get("mode") != "native" {
				t.Errorf("wrong mode")
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"id": "session-1"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c, err := New(srv.URL, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Login(context.Background(), "user", "pass"); err != nil {
		t.Fatal(err)
	}
	accounts, err := c.Accounts(context.Background(), "asset-1")
	if err != nil || len(accounts) != 1 {
		t.Fatalf("accounts=%v err=%v", accounts, err)
	}
	s, err := c.CreateSession(context.Background(), "asset-1", accounts[0].ID, "native")
	if err != nil || s.ID != "session-1" {
		t.Fatalf("session=%v err=%v", s, err)
	}
	if !sawAuth {
		t.Fatal("runtime token was not reused")
	}
	if cookie := c.WebSocketHeaders().Get("Cookie"); !strings.Contains(cookie, "sid=cookie-secret") {
		t.Fatal("runtime login cookie was not exposed to websocket transport")
	}
	cookies := c.BrowserCookies()
	if len(cookies) != 1 || cookies[0].Name != "sid" || cookies[0].Value != "cookie-secret" {
		t.Fatalf("runtime login cookie was not exposed to browser transport: %+v", cookies)
	}
}

func TestErrorsNeverExposeSecretsOrLargeBodies(t *testing.T) {
	secret := "do-not-log-this"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(strings.Repeat("x", 9000) + secret))
	}))
	defer srv.Close()
	c, _ := New(srv.URL, Options{MaxErrorBody: 128})
	err := c.Login(context.Background(), "user", secret)
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), secret) || len(err.Error()) > 512 {
		t.Fatalf("unsafe error: %q", err)
	}
}

func TestCompleteSessionLifecycleEndpoints(t *testing.T) {
	seen := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen[r.Method+" "+r.URL.Path]++
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/session-review-tasks/candidates":
			if r.URL.Query().Get("assetId") != "asset-1" {
				t.Error("missing assetId")
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []Candidate{}})
		case r.Method == http.MethodPost && r.URL.Path == "/sessions/session-1/connect":
			w.WriteHeader(204)
		case r.Method == http.MethodGet && r.URL.Path == "/sessions/session-1":
			_ = json.NewEncoder(w).Encode(Session{ID: "session-1", Status: "connected"})
		case r.Method == http.MethodPost && r.URL.Path == "/db-sessions":
			_ = json.NewEncoder(w).Encode(Session{ID: "db-1"})
		case r.Method == http.MethodPost && r.URL.Path == "/webpam/sessions":
			_ = json.NewEncoder(w).Encode(Session{ID: "web-1"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c, _ := New(srv.URL, Options{})
	if _, err := c.ReviewCandidates(context.Background(), "asset-1"); err != nil {
		t.Fatal(err)
	}
	if err := c.Connect(context.Background(), "session-1"); err != nil {
		t.Fatal(err)
	}
	if s, err := c.SessionStatus(context.Background(), "session-1"); err != nil || s.Status != "connected" {
		t.Fatalf("status=%+v err=%v", s, err)
	}
	if s, err := c.CreateDBSession(context.Background(), "asset-1", "account-1"); err != nil || s.ID != "db-1" {
		t.Fatalf("db=%+v err=%v", s, err)
	}
	if s, err := c.CreateWebSession(context.Background(), "asset-1", "account-1"); err != nil || s.ID != "web-1" {
		t.Fatalf("web=%+v err=%v", s, err)
	}
	if len(seen) != 5 {
		t.Fatalf("seen=%v", seen)
	}
}

func TestCreateWebSessionDecodesPAMDataEnvelope(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/webpam/sessions" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"code": 1,
			"data": map[string]any{
				"sessionId": "web-envelope-1",
				"status":    "connecting",
			},
			"message": "ok",
		})
	}))
	defer srv.Close()

	c, err := New(srv.URL, Options{})
	if err != nil {
		t.Fatal(err)
	}
	session, err := c.CreateWebSession(context.Background(), "asset-1", "account-1")
	if err != nil {
		t.Fatal(err)
	}
	if session.ID != "web-envelope-1" || session.Status != "connecting" {
		t.Fatalf("session=%+v", session)
	}
}

func TestWaitConnectedPollsUntilReady(t *testing.T) {
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		status := "connecting"
		if requests >= 3 {
			status = "connected"
		}
		_ = json.NewEncoder(w).Encode(Session{ID: "s", Status: status})
	}))
	defer srv.Close()
	c, _ := New(srv.URL, Options{})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	s, err := c.WaitConnected(ctx, "s", 5*time.Millisecond)
	if err != nil || s.Status != "connected" || requests != 3 {
		t.Fatalf("session=%+v requests=%d err=%v", s, requests, err)
	}
}

func TestWaitConnectedStopsImmediatelyOnNoConnect(t *testing.T) {
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		_ = json.NewEncoder(w).Encode(Session{ID: "sensitive-session-id", Status: "no_connect"})
	}))
	defer srv.Close()
	c, _ := New(srv.URL, Options{})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := c.WaitConnected(ctx, "sensitive-session-id", 5*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "no_connect") {
		t.Fatalf("err=%v", err)
	}
	if requests != 1 {
		t.Fatalf("requests=%d", requests)
	}
	if strings.Contains(err.Error(), "sensitive-session-id") {
		t.Fatalf("error leaked session ID: %v", err)
	}
}

func TestClientUnwrapsPAMResponseEnvelope(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/login":
			_ = json.NewEncoder(w).Encode(map[string]any{"code": 1, "data": map[string]any{"info": map[string]string{"username": "u"}}, "message": ""})
		case strings.HasSuffix(r.URL.Path, "/accounts"):
			_ = json.NewEncoder(w).Encode(map[string]any{"code": 1, "data": []Account{{ID: "account-1"}}, "message": ""})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c, _ := New(srv.URL, Options{})
	if err := c.Login(context.Background(), "u", "p"); err != nil {
		t.Fatal(err)
	}
	accounts, err := c.Accounts(context.Background(), "a")
	if err != nil || len(accounts) != 1 || accounts[0].ID != "account-1" {
		t.Fatalf("accounts=%v err=%v", accounts, err)
	}
}

func TestClientRejectsPAMEnvelopeErrorWithoutLeakingBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"code": 0, "data": nil, "message": "authentication rejected"})
	}))
	defer srv.Close()
	c, _ := New(srv.URL, Options{})
	err := c.Login(context.Background(), "u", "p")
	if err == nil || !strings.Contains(err.Error(), "authentication rejected") {
		t.Fatalf("err=%v", err)
	}
}

func TestLoginUsesWrappedSM2CryptoKey(t *testing.T) {
	var sawEncrypted bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login/crypto-key":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"code": 1,
				"data": map[string]string{
					"publicKey":  "047AE4D5CEDF92B910CF22CF1E976B8C3F8C081B7CADEAB1839C895D1706969A0BA8351096B26D43C6DDEF56302001C0BFD7B30ED9B25168FB755AE26047FE0CA7",
					"cipherMode": "C1C3C2",
				},
				"message": "success",
			})
		case "/login":
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			encrypted, ok := payload["encryptedPassword"].(string)
			sawEncrypted = ok && encrypted != ""
			if !sawEncrypted {
				t.Fatalf("login payload did not use encryptedPassword: %#v", payload)
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"token": "runtime-secret"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	c, err := New(srv.URL, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Login(context.Background(), "superadmin", "emmEMM2023@leagsoft"); err != nil {
		t.Fatal(err)
	}
	if !sawEncrypted || c.Token() != "runtime-secret" {
		t.Fatalf("encrypted=%v token=%q", sawEncrypted, c.Token())
	}
}

func TestLoginDoesNotFallBackToPlaintextAfterEncryptedLoginRejection(t *testing.T) {
	loginCalls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login/crypto-key":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"code": 1,
				"data": map[string]string{
					"publicKey":  "047AE4D5CEDF92B910CF22CF1E976B8C3F8C081B7CADEAB1839C895D1706969A0BA8351096B26D43C6DDEF56302001C0BFD7B30ED9B25168FB755AE26047FE0CA7",
					"cipherMode": "C1C3C2",
				},
				"message": "success",
			})
		case "/login":
			loginCalls++
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			if _, ok := payload["password"]; ok {
				t.Fatalf("login fell back to plaintext payload after encrypted rejection: %#v", payload)
			}
			http.Error(w, `{"code":403,"message":"forbidden"}`, http.StatusForbidden)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	c, err := New(srv.URL, Options{})
	if err != nil {
		t.Fatal(err)
	}
	err = c.Login(context.Background(), "superadmin", "secret")
	if err == nil || !strings.Contains(err.Error(), "returned 403") {
		t.Fatalf("err=%v", err)
	}
	if loginCalls != 1 {
		t.Fatalf("login calls=%d, want 1", loginCalls)
	}
}

func TestNewClientCanUsePresetRuntimeToken(t *testing.T) {
	var sawAuth bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/login":
			t.Fatal("preset token client should not need login")
		case strings.HasSuffix(r.URL.Path, "/accounts"):
			sawAuth = r.Header.Get("X-Auth-Token") == "runtime-secret"
			_ = json.NewEncoder(w).Encode([]Account{{ID: "account-1"}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	c, err := New(srv.URL, Options{Token: "runtime-secret"})
	if err != nil {
		t.Fatal(err)
	}
	if c.Token() != "runtime-secret" {
		t.Fatalf("token=%q", c.Token())
	}
	if _, err := c.Accounts(context.Background(), "asset-1"); err != nil {
		t.Fatal(err)
	}
	if !sawAuth {
		t.Fatal("preset runtime token was not sent")
	}
}

func TestNewClientCanUsePresetRuntimeCookie(t *testing.T) {
	var sawCookie bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/login":
			t.Fatal("preset cookie client should not need login")
		case strings.HasSuffix(r.URL.Path, "/accounts"):
			for _, cookie := range r.Cookies() {
				if cookie.Name == "sid" && cookie.Value == "runtime-cookie" {
					sawCookie = true
				}
			}
			_ = json.NewEncoder(w).Encode([]Account{{ID: "account-1"}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	c, err := New(srv.URL, Options{Cookies: []http.Cookie{{Name: "sid", Value: "runtime-cookie", Path: "/"}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Accounts(context.Background(), "asset-1"); err != nil {
		t.Fatal(err)
	}
	if !sawCookie {
		t.Fatal("preset runtime cookie was not sent")
	}
}

func TestWebDirectControlEndpoints(t *testing.T) {
	seen := map[string]json.RawMessage{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body json.RawMessage
		if r.Body != nil {
			_ = json.NewDecoder(r.Body).Decode(&body)
		}
		seen[r.Method+" "+r.URL.Path] = body
		switch r.URL.Path {
		case "/sessions/web-1/web/webrtc/offer":
			_ = json.NewEncoder(w).Encode(WebRTCAnswer{Mode: "webrtc", Media: "frames", Answer: WebRTCDescription{Type: "answer", SDP: "answer-sdp"}})
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{})
		}
	}))
	defer srv.Close()
	c, _ := New(srv.URL, Options{})
	answer, err := c.WebRTCOffer(context.Background(), "web-1", WebRTCOffer{Type: "offer", SDP: "offer-sdp", Width: 1280, Height: 720})
	if err != nil || answer.Answer.SDP != "answer-sdp" {
		t.Fatalf("answer=%+v err=%v", answer, err)
	}
	mid := "0"
	line := uint16(0)
	if err := c.WebRTCCandidate(context.Background(), "web-1", WebRTCCandidate{Candidate: "candidate", SDPMid: &mid, SDPMLineIndex: &line}); err != nil {
		t.Fatal(err)
	}
	if err := c.WebNavigate(context.Background(), "web-1", "reload"); err != nil {
		t.Fatal(err)
	}
	if err := c.WebResize(context.Background(), "web-1", 1280, 720); err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range []string{
		"POST /sessions/web-1/web/webrtc/offer",
		"POST /sessions/web-1/web/webrtc/candidate",
		"POST /sessions/web-1/web/navigation",
		"POST /webpam/sessions/web-1/resize",
	} {
		if _, ok := seen[endpoint]; !ok {
			t.Fatalf("missing endpoint %s: %v", endpoint, seen)
		}
	}
}

func TestCloseWebSessionUsesDedicatedEndpoint(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/webpam/sessions/web-1/close" {
			http.NotFound(w, r)
			return
		}
		called = true
		_ = json.NewEncoder(w).Encode(map[string]any{"code": 1, "data": nil, "message": "success"})
	}))
	defer srv.Close()

	c, _ := New(srv.URL, Options{})
	if err := c.CloseWebSession(context.Background(), "web-1"); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("dedicated WebPAM close endpoint was not called")
	}
}

func TestCloseWebSessionRedactsShortSessionIDFromErrors(t *testing.T) {
	const sessionID = "short-session-id"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "close failed", http.StatusInternalServerError)
	}))
	defer srv.Close()

	c, _ := New(srv.URL, Options{})
	err := c.CloseWebSession(context.Background(), sessionID)
	if err == nil {
		t.Fatal("expected close failure")
	}
	if strings.Contains(err.Error(), sessionID) || !strings.Contains(err.Error(), "/webpam/sessions/{id}/close") {
		t.Fatalf("session ID was not redacted: %v", err)
	}
}
