package pam

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	"pam-loadtest/internal/sm2login"
)

type Options struct {
	Timeout      time.Duration
	MaxErrorBody int64
	Token        string
	Cookies      []http.Cookie
}
type Client struct {
	base         *url.URL
	http         *http.Client
	token        string
	maxErrorBody int64
}
type Account struct {
	ID string `json:"id"`
}
type Candidate struct {
	ID string `json:"id"`
}
type Session struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

type WebRTCDescription struct {
	Type string `json:"type"`
	SDP  string `json:"sdp"`
}

type WebRTCOffer struct {
	Type    string `json:"type"`
	SDP     string `json:"sdp"`
	Width   int    `json:"width"`
	Height  int    `json:"height"`
	FPS     int    `json:"fps"`
	Quality string `json:"quality"`
}

type WebRTCAnswer struct {
	Mode     string            `json:"mode"`
	Media    string            `json:"media"`
	State    string            `json:"state"`
	Fallback bool              `json:"fallback"`
	Reason   string            `json:"reason"`
	Answer   WebRTCDescription `json:"answer"`
}

type WebRTCCandidate struct {
	Candidate        string  `json:"candidate"`
	SDPMid           *string `json:"sdpMid,omitempty"`
	SDPMLineIndex    *uint16 `json:"sdpMLineIndex,omitempty"`
	UsernameFragment *string `json:"usernameFragment,omitempty"`
}

func New(baseURL string, opts Options) (*Client, error) {
	u, err := url.Parse(baseURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("invalid PAM base URL")
	}
	jar, _ := cookiejar.New(nil)
	if opts.Timeout == 0 {
		opts.Timeout = 30 * time.Second
	}
	if opts.MaxErrorBody == 0 {
		opts.MaxErrorBody = 1024
	}
	if len(opts.Cookies) > 0 {
		cookies := make([]*http.Cookie, 0, len(opts.Cookies))
		for i := range opts.Cookies {
			cookies = append(cookies, &opts.Cookies[i])
		}
		jar.SetCookies(u, cookies)
	}
	return &Client{base: u, http: &http.Client{Timeout: opts.Timeout, Jar: jar}, token: opts.Token, maxErrorBody: opts.MaxErrorBody}, nil
}

func (c *Client) Login(ctx context.Context, username, password string) error {
	var response map[string]any
	// Newer SGP-PAM builds require the password to be SM2-encrypted.
	// Fall back to the legacy plaintext flow only when the crypto-key endpoint
	// is unavailable; once PAM rejects encrypted login, preserve that error.
	if encrypted, err := c.sm2EncryptedPassword(ctx, password); err == nil {
		payload := map[string]any{"username": username, "remember": false, "encryptedPassword": encrypted}
		if err := c.doJSON(ctx, http.MethodPost, "/login", nil, payload, &response); err != nil {
			return err
		}
		return c.applyToken(response)
	}
	response = map[string]any{}
	if err := c.doJSON(ctx, http.MethodPost, "/login", nil, map[string]string{"username": username, "password": password}, &response); err != nil {
		return err
	}
	return c.applyToken(response)
}

// sm2EncryptedPassword fetches the PAM SM2 login public key and encrypts the
// password for the newer /login flow. It returns an error when the
// crypto-key endpoint is unavailable so the caller can fall back to the
// legacy plaintext login.
func (c *Client) sm2EncryptedPassword(ctx context.Context, password string) (string, error) {
	var keyResp struct {
		PublicKey  string `json:"publicKey"`
		CipherMode string `json:"cipherMode"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/login/crypto-key", nil, nil, &keyResp); err != nil {
		return "", err
	}
	if keyResp.PublicKey == "" {
		return "", fmt.Errorf("PAM login crypto-key unavailable")
	}
	return sm2login.EncryptPassword(password, keyResp.PublicKey, keyResp.CipherMode)
}

func (c *Client) applyToken(response map[string]any) error {
	for _, key := range []string{"token", "accessToken", "access_token"} {
		if v, ok := response[key].(string); ok && v != "" {
			c.token = v
			break
		}
	}
	return nil
}

func (c *Client) Accounts(ctx context.Context, assetID string) ([]Account, error) {
	var accounts []Account
	err := c.doJSON(ctx, http.MethodGet, "/worker/assets/"+url.PathEscape(assetID)+"/accounts", nil, nil, &accounts)
	return accounts, err
}

func (c *Client) CreateSession(ctx context.Context, assetID, accountID, mode string) (Session, error) {
	q := url.Values{"assetId": {assetID}, "accountId": {accountID}, "mode": {mode}}
	var s Session
	err := c.doJSON(ctx, http.MethodPost, "/sessions", q, nil, &s)
	return s, err
}

func (c *Client) ReviewCandidates(ctx context.Context, assetID string) ([]Candidate, error) {
	var candidates candidateList
	err := c.doJSON(ctx, http.MethodGet, "/session-review-tasks/candidates", url.Values{"assetId": {assetID}}, nil, &candidates)
	return []Candidate(candidates), err
}

type candidateList []Candidate

func (c *candidateList) UnmarshalJSON(data []byte) error {
	var direct []Candidate
	if json.Unmarshal(data, &direct) == nil {
		*c = direct
		return nil
	}
	var page struct {
		Items []Candidate `json:"items"`
	}
	if err := json.Unmarshal(data, &page); err != nil {
		return err
	}
	*c = page.Items
	return nil
}

func (c *Client) Connect(ctx context.Context, sessionID string) error {
	return c.doJSON(ctx, http.MethodPost, "/sessions/"+url.PathEscape(sessionID)+"/connect", nil, nil, nil)
}

func (c *Client) SessionStatus(ctx context.Context, sessionID string) (Session, error) {
	var current Session
	err := c.doJSON(ctx, http.MethodGet, "/sessions/"+url.PathEscape(sessionID), nil, nil, &current)
	return current, err
}

func (c *Client) WaitConnected(ctx context.Context, sessionID string, interval time.Duration) (Session, error) {
	if interval <= 0 {
		interval = 250 * time.Millisecond
	}
	for {
		current, err := c.SessionStatus(ctx, sessionID)
		if err != nil {
			return Session{}, err
		}
		if current.Status == "connected" || current.Status == "active" {
			return current, nil
		}
		if current.Status == "failed" || current.Status == "closed" || current.Status == "no_connect" {
			return current, fmt.Errorf("PAM session entered %s state", Redact(current.Status))
		}
		select {
		case <-ctx.Done():
			return current, ctx.Err()
		case <-time.After(interval):
		}
	}
}

func (c *Client) CreateDBSession(ctx context.Context, assetID, accountID string) (Session, error) {
	var current Session
	err := c.doJSON(ctx, http.MethodPost, "/db-sessions", nil, map[string]string{"assetId": assetID, "accountId": accountID}, &current)
	return current, err
}

func (c *Client) CreateWebSession(ctx context.Context, assetID, accountID string) (Session, error) {
	var response struct {
		ID        string `json:"id"`
		SessionID string `json:"sessionId"`
		Status    string `json:"status"`
	}
	err := c.doJSON(ctx, http.MethodPost, "/webpam/sessions", nil, map[string]string{"assetId": assetID, "accountId": accountID}, &response)
	if err != nil {
		return Session{}, err
	}
	if response.ID == "" {
		response.ID = response.SessionID
	}
	return Session{ID: response.ID, Status: response.Status}, nil
}

func (c *Client) WebRTCOffer(ctx context.Context, sessionID string, offer WebRTCOffer) (WebRTCAnswer, error) {
	var answer WebRTCAnswer
	err := c.doJSON(ctx, http.MethodPost, "/sessions/"+url.PathEscape(sessionID)+"/web/webrtc/offer", nil, offer, &answer)
	return answer, err
}

func (c *Client) WebRTCCandidate(ctx context.Context, sessionID string, candidate WebRTCCandidate) error {
	return c.doJSON(ctx, http.MethodPost, "/sessions/"+url.PathEscape(sessionID)+"/web/webrtc/candidate", nil, candidate, nil)
}

func (c *Client) WebNavigate(ctx context.Context, sessionID, action string) error {
	return c.doJSON(ctx, http.MethodPost, "/sessions/"+url.PathEscape(sessionID)+"/web/navigation", nil, map[string]string{"action": action}, nil)
}

func (c *Client) WebResize(ctx context.Context, sessionID string, width, height int) error {
	return c.doJSON(ctx, http.MethodPost, "/webpam/sessions/"+url.PathEscape(sessionID)+"/resize", nil, map[string]int{"width": width, "height": height}, nil)
}

func (c *Client) CloseWebSession(ctx context.Context, sessionID string) error {
	return c.doJSON(ctx, http.MethodPost, "/webpam/sessions/"+url.PathEscape(sessionID)+"/close", nil, map[string]any{}, nil)
}

func (c *Client) Token() string   { return c.token }
func (c *Client) BaseURL() string { return c.base.String() }
func (c *Client) BrowserCookies() []http.Cookie {
	if c.http.Jar == nil {
		return nil
	}
	stored := c.http.Jar.Cookies(c.base)
	cookies := make([]http.Cookie, 0, len(stored))
	for _, cookie := range stored {
		if cookie != nil {
			cookies = append(cookies, *cookie)
		}
	}
	return cookies
}
func (c *Client) WebSocketHeaders() http.Header {
	headers := make(http.Header)
	request := &http.Request{Header: headers}
	for _, cookie := range c.http.Jar.Cookies(c.base) {
		request.AddCookie(cookie)
	}
	if c.token != "" {
		headers.Set("X-Auth-Token", c.token)
	}
	return headers
}

func (c *Client) doJSON(ctx context.Context, method, path string, query url.Values, body any, out any) error {
	u := c.base.ResolveReference(&url.URL{Path: path})
	if query != nil {
		u.RawQuery = query.Encode()
	}
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), reader)
	if err != nil {
		return fmt.Errorf("build PAM request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("X-Auth-Token", c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("PAM %s %s: %w", method, RedactPath(path), err)
	}
	defer resp.Body.Close()
	if token := resp.Header.Get("X-Auth-Token"); token != "" {
		c.token = token
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, c.maxErrorBody))
		return fmt.Errorf("PAM %s %s returned %d: %s", method, RedactPath(path), resp.StatusCode, Redact(strings.TrimSpace(string(b))))
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return nil
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, (4<<20)+1))
	if err != nil {
		return fmt.Errorf("read PAM %s %s response: %w", method, RedactPath(path), err)
	}
	if len(raw) > 4<<20 {
		return fmt.Errorf("PAM %s %s response exceeds limit", method, RedactPath(path))
	}
	payload := raw
	var envelope map[string]json.RawMessage
	if json.Unmarshal(raw, &envelope) == nil {
		if codeRaw, ok := envelope["code"]; ok {
			var code int
			if err := json.Unmarshal(codeRaw, &code); err != nil {
				return fmt.Errorf("decode PAM %s %s response code", method, RedactPath(path))
			}
			if code != 1 {
				var message string
				_ = json.Unmarshal(envelope["message"], &message)
				message = Redact(message)
				if len(message) > 256 {
					message = message[:256]
				}
				return fmt.Errorf("PAM %s %s rejected request: %s", method, RedactPath(path), message)
			}
			if data, exists := envelope["data"]; exists {
				payload = data
			}
		}
	}
	if err := json.Unmarshal(payload, out); err != nil {
		return fmt.Errorf("decode PAM %s %s response: %w", method, RedactPath(path), err)
	}
	return nil
}
