package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestProxyRejectsMissingTokenID(t *testing.T) {
	app := NewApp(&Config{})

	req := httptest.NewRequest(http.MethodPost, "/proxy", strings.NewReader(`{"session_id":"si:test"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	app.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d with body %s", rec.Code, rec.Body.String())
	}
	var response proxyResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if response.Success {
		t.Fatal("expected missing token_id response to be unsuccessful")
	}
	if !strings.Contains(response.Error, "token_id") {
		t.Fatalf("expected token_id error, got %q", response.Error)
	}
}

func TestProxyRejectsSessionIDLongerThanProtocolField(t *testing.T) {
	app := NewApp(&Config{})
	requestBody := fmt.Sprintf(`{"token_id":"token","session_id":"%s"}`, strings.Repeat("s", 41))
	req := httptest.NewRequest(http.MethodPost, "/proxy", strings.NewReader(requestBody))
	rec := httptest.NewRecorder()

	app.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d with body %s", rec.Code, rec.Body.String())
	}
}

func TestProxyRejectsOversizedRequestBody(t *testing.T) {
	app := NewApp(&Config{})
	requestBody := fmt.Sprintf(`{"token_id":"%s","session_id":"si:test"}`, strings.Repeat("t", 70<<10))
	req := httptest.NewRequest(http.MethodPost, "/proxy", strings.NewReader(requestBody))
	rec := httptest.NewRecorder()

	app.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected status 413, got %d with body %s", rec.Code, rec.Body.String())
	}
}

func TestProxyRejectsTrailingJSONValue(t *testing.T) {
	app := NewApp(&Config{})
	req := httptest.NewRequest(http.MethodPost, "/proxy", strings.NewReader(`{"token_id":"token","session_id":"si:test"} {}`))
	rec := httptest.NewRecorder()

	app.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d with body %s", rec.Code, rec.Body.String())
	}
}

func TestEncodeTokenIDFromSPAResponse(t *testing.T) {
	tokenID, err := encodeTokenID(map[string]interface{}{
		"timestamp": float64(12345),
		"nonce":     "nonce-value",
		"token":     "token-value",
	}, "device-1")
	if err != nil {
		t.Fatalf("encodeTokenID failed: %v", err)
	}

	decoded, err := base64.StdEncoding.DecodeString(tokenID)
	if err != nil {
		t.Fatalf("token_id is not base64: %v", err)
	}
	var info TokenInfo
	if err := json.Unmarshal(decoded, &info); err != nil {
		t.Fatalf("token_id did not decode to TokenInfo: %v", err)
	}

	if info.DevID != "device-1" || info.Timestamp != 12345 || info.Nonce != "nonce-value" || info.Token != "token-value" {
		t.Fatalf("unexpected token info: %+v", info)
	}
}

func TestEncodeTokenIDReportsUpstreamResponseWhenTimestampMissing(t *testing.T) {
	_, err := encodeTokenID(map[string]interface{}{
		"code":    float64(401),
		"message": "auth failed",
	}, "device-1")
	if err == nil {
		t.Fatal("expected missing timestamp to return an error")
	}

	message := err.Error()
	if !strings.Contains(message, "timestamp 字段缺失") {
		t.Fatalf("expected timestamp error, got %q", message)
	}
	if !strings.Contains(message, `"code":401`) || !strings.Contains(message, `"message":"auth failed"`) {
		t.Fatalf("expected upstream response in error, got %q", message)
	}
}

func TestEncodeTokenIDRedactsSensitiveUpstreamFieldsFromErrors(t *testing.T) {
	secretToken := "full-upstream-token-secret"
	_, err := encodeTokenID(map[string]interface{}{
		"message":  "auth failed",
		"token":    secretToken,
		"password": "echoed-password",
	}, "device-1")
	if err == nil {
		t.Fatal("expected missing timestamp to return an error")
	}

	message := err.Error()
	if strings.Contains(message, secretToken) || strings.Contains(message, "echoed-password") {
		t.Fatalf("error contains sensitive upstream fields: %q", message)
	}
	if !strings.Contains(message, "[REDACTED]") {
		t.Fatalf("error does not show redaction marker: %q", message)
	}
}

func TestReceiveSPAResponseRejectsOversizedBodyBeforeAllocation(t *testing.T) {
	header := make([]byte, 20)
	binary.BigEndian.PutUint32(header[0:4], 0x5350413A)
	binary.BigEndian.PutUint16(header[4:6], 1)
	binary.BigEndian.PutUint16(header[6:8], AUTH_REQUEST)
	header[8] = JSON
	binary.BigEndian.PutUint32(header[12:16], uint32((1<<20)+1))
	conn := &scriptedConn{readChunks: [][]byte{header}}

	_, err := receiveSPAResponse(conn, time.Second)

	if err == nil || !strings.Contains(err.Error(), "超过上限") {
		t.Fatalf("expected oversized response error, got %v", err)
	}
}

func TestReceiveSPAResponseRejectsInvalidProtocolTag(t *testing.T) {
	header := make([]byte, 20)
	binary.BigEndian.PutUint32(header[0:4], 0x11111111)
	binary.BigEndian.PutUint16(header[4:6], 1)
	header[8] = JSON
	binary.BigEndian.PutUint32(header[12:16], 2)
	conn := &scriptedConn{readChunks: [][]byte{header, []byte("{}")}}

	_, err := receiveSPAResponse(conn, time.Second)

	if err == nil || !strings.Contains(err.Error(), "Tag") {
		t.Fatalf("expected invalid SPA tag error, got %v", err)
	}
}

func TestReceiveSPAResponseAcceptsServerProtoTypeFourWithJSONBody(t *testing.T) {
	body := []byte(`{"timestamp":123,"nonce":"nonce","token":"token"}`)
	header := make([]byte, 20)
	binary.BigEndian.PutUint32(header[0:4], 0x5350413A)
	binary.BigEndian.PutUint16(header[4:6], 1)
	header[8] = 4
	binary.BigEndian.PutUint32(header[12:16], uint32(len(body)))
	conn := &scriptedConn{readChunks: [][]byte{header, body}}

	response, err := receiveSPAResponse(conn, time.Second)

	if err != nil {
		t.Fatalf("expected ProtoType 4 JSON response to be accepted: %v", err)
	}
	if response["token"] != "token" {
		t.Fatalf("unexpected response: %#v", response)
	}
}

func TestAuthRejectsMissingPasswordWhenNoDefaultConfigured(t *testing.T) {
	app := NewApp(&Config{})

	req := httptest.NewRequest(http.MethodPost, "/auth", strings.NewReader(`{"username":"tester1","devid":"device-1"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	app.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d with body %s", rec.Code, rec.Body.String())
	}
	var response authResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if response.Success {
		t.Fatal("expected missing password response to be unsuccessful")
	}
	if !strings.Contains(response.Error, "password") {
		t.Fatalf("expected password error, got %q", response.Error)
	}
}

func TestAuthRejectsMissingPasswordEvenWhenConfigFileContainsAuthPassword(t *testing.T) {
	configFile := writeTempConfig(t, `{
		"listen_addr": ":0",
		"quic_host": "127.0.0.1",
		"quic_port": "40233",
		"tls_host": "127.0.0.1",
		"tls_port": "8002",
		"auth_password": "real-default"
	}`)
	config, err := loadConfig(configFile)
	if err != nil {
		t.Fatalf("loadConfig failed: %v", err)
	}
	app := NewApp(config)

	req := httptest.NewRequest(http.MethodPost, "/auth", strings.NewReader(`{"username":"tester1","devid":"device-1"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	app.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d with body %s", rec.Code, rec.Body.String())
	}
	var response authResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if response.Success {
		t.Fatal("expected missing password response to be unsuccessful")
	}
	if !strings.Contains(response.Error, "password") {
		t.Fatalf("expected password error, got %q", response.Error)
	}
}

func TestAuthRejectsPlaceholderPassword(t *testing.T) {
	app := NewApp(&Config{})

	req := httptest.NewRequest(http.MethodPost, "/auth", strings.NewReader(`{"username":"tester1","devid":"device-1","password":"optional"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	app.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d with body %s", rec.Code, rec.Body.String())
	}
	var response authResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if response.Success {
		t.Fatal("expected placeholder password response to be unsuccessful")
	}
	if !strings.Contains(response.Error, "password") {
		t.Fatalf("expected password error, got %q", response.Error)
	}
}

func TestBuildRequestBytesUsesConfiguredMethodHeadersAndBody(t *testing.T) {
	config := &Config{
		RequestHost:   "10.0.0.8",
		RequestPort:   "9091",
		RequestPath:   "/api/check",
		RequestMethod: "POST",
		RequestHeaders: map[string]string{
			"X-Test":         "yes",
			"Content-Length": "999",
		},
		RequestBody: "hello",
	}

	request, err := buildRequestBytes(config)
	if err != nil {
		t.Fatalf("buildRequestBytes failed: %v", err)
	}
	got := string(request)
	expectedParts := []string{
		"POST /api/check HTTP/1.1\r\n",
		"Host: 10.0.0.8:9091\r\n",
		"User-Agent: curl/7.68.0\r\n",
		"Accept: */*\r\n",
		"Connection: close\r\n",
		"Content-Length: 5\r\n",
		"X-Test: yes\r\n",
		"\r\nhello",
	}
	for _, part := range expectedParts {
		if !strings.Contains(got, part) {
			t.Fatalf("request missing %q:\n%s", part, got)
		}
	}
	if strings.Contains(got, "Content-Length: 999") {
		t.Fatalf("request used configured Content-Length instead of computed length:\n%s", got)
	}
}

func TestBuildRequestBytesUsesRawRequest(t *testing.T) {
	config := &Config{
		UseRawRequest: true,
		RawRequest:    "GET /raw HTTP/1.1\r\nHost: raw.example\r\n\r\n",
	}

	request, err := buildRequestBytes(config)
	if err != nil {
		t.Fatalf("buildRequestBytes failed: %v", err)
	}
	if got := string(request); got != config.RawRequest {
		t.Fatalf("request = %q, want %q", got, config.RawRequest)
	}
}

func TestWriteAllHandlesShortWrites(t *testing.T) {
	writer := &shortWriter{max: 3}
	data := []byte("complete payload")

	if err := writeAll(writer, data); err != nil {
		t.Fatalf("writeAll failed: %v", err)
	}
	if got := writer.buffer.String(); got != string(data) {
		t.Fatalf("written data = %q, want %q", got, data)
	}
}

func TestSendTCPHelloExtractsStatusAndBody(t *testing.T) {
	conn := &scriptedConn{readChunks: [][]byte{
		[]byte("HTTP/1.1 201 Created\r\nContent-Length: 10\r\n\r\ncreated ok"),
	}}
	client := &Client{config: &Config{
		RequestBytes:         []byte("GET /hello HTTP/1.1\r\nHost: test\r\n\r\n"),
		ReturnUpstreamBody:   true,
		UpstreamBodyMaxBytes: 64,
	}}

	response := client.sendTCPHello(conn)

	if !response.Success {
		t.Fatal("expected 201 response to be successful")
	}
	if response.StatusLine != "HTTP/1.1 201 Created" {
		t.Fatalf("status line = %q", response.StatusLine)
	}
	if response.StatusCode != 201 {
		t.Fatalf("status code = %d", response.StatusCode)
	}
	if response.Body != "created ok" {
		t.Fatalf("body = %q", response.Body)
	}
	if response.Bytes == 0 {
		t.Fatal("expected byte count to be set")
	}
}

func TestSendTCPHelloOmitsBodyWhenDisabled(t *testing.T) {
	conn := &scriptedConn{readChunks: [][]byte{
		[]byte("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\ncreated ok"),
	}}
	client := &Client{config: &Config{
		RequestBytes:       []byte("GET /hello HTTP/1.1\r\nHost: test\r\n\r\n"),
		ReturnUpstreamBody: false,
	}}

	response := client.sendTCPHello(conn)

	if !response.Success {
		t.Fatal("expected 200 response to be successful")
	}
	if response.StatusCode != 200 {
		t.Fatalf("status code = %d", response.StatusCode)
	}
	if response.Body != "" {
		t.Fatalf("body = %q, want empty body", response.Body)
	}
	if response.Bytes != 0 {
		t.Fatalf("bytes = %d, want zero when body is disabled", response.Bytes)
	}
}

func TestSendTCPHelloDebugLoggingDoesNotExposeDisabledBody(t *testing.T) {
	logFile := t.TempDir() + "/app.log"
	closer, err := setupLogger(&Config{LogFile: logFile, LogLevel: "debug"})
	if err != nil {
		t.Fatalf("setupLogger failed: %v", err)
	}
	defer slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	conn := &scriptedConn{readChunks: [][]byte{
		[]byte("HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nsecret"),
	}}
	client := &Client{config: &Config{
		RequestBytes:         []byte("GET /hello HTTP/1.1\r\nHost: test\r\n\r\n"),
		ReturnUpstreamBody:   false,
		UpstreamBodyMaxBytes: 64,
	}}

	response := client.sendTCPHello(conn)
	if err := closer.Close(); err != nil {
		t.Fatalf("close logger failed: %v", err)
	}

	if response.Body != "" {
		t.Fatalf("body = %q, want empty body when return_upstream_body is false", response.Body)
	}
	logData, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("read log failed: %v", err)
	}
	if !strings.Contains(string(logData), "secret") {
		t.Fatalf("debug log does not contain captured body: %s", logData)
	}
}

func TestSendTCPHelloDoesNotDrainBodyWhenReturnBodyIsDisabled(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	done := make(chan BusinessResponse, 1)
	go func() {
		client := &Client{config: &Config{
			RequestBytes:          []byte("GET /hello HTTP/1.1\r\nHost: test\r\n\r\n"),
			ReturnUpstreamBody:    false,
			TCPOperationTimeoutMS: 3000,
		}}
		done <- client.sendTCPHello(clientConn)
	}()

	request := make([]byte, 512)
	if _, err := serverConn.Read(request); err != nil {
		t.Fatalf("read request failed: %v", err)
	}
	if _, err := serverConn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\n\r\n")); err != nil {
		t.Fatalf("write response failed: %v", err)
	}

	select {
	case response := <-done:
		if !response.Success {
			t.Fatalf("expected successful response: %+v", response)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("disabled response body was drained instead of returning after headers")
	}
}

func TestSendTCPHelloDoesNotDrainBodyAfterTruncation(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	done := make(chan BusinessResponse, 1)
	go func() {
		client := &Client{config: &Config{
			RequestBytes:          []byte("GET /hello HTTP/1.1\r\nHost: test\r\n\r\n"),
			ReturnUpstreamBody:    true,
			UpstreamBodyMaxBytes:  3,
			TCPOperationTimeoutMS: 3000,
		}}
		done <- client.sendTCPHello(clientConn)
	}()

	request := make([]byte, 512)
	if _, err := serverConn.Read(request); err != nil {
		t.Fatalf("read request failed: %v", err)
	}
	if _, err := serverConn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nabcd")); err != nil {
		t.Fatalf("write response failed: %v", err)
	}

	select {
	case response := <-done:
		if !response.Success || !response.BodyTruncated || response.Body != "abc" {
			t.Fatalf("unexpected truncated response: %+v", response)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("truncated response body was drained instead of returning at the configured limit")
	}
}

func TestSendTCPHelloTruncatesBodyWhenLimitConfigured(t *testing.T) {
	conn := &scriptedConn{readChunks: [][]byte{
		[]byte("HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nabcdef"),
	}}
	client := &Client{config: &Config{
		RequestBytes:         []byte("GET /hello HTTP/1.1\r\nHost: test\r\n\r\n"),
		ReturnUpstreamBody:   true,
		UpstreamBodyMaxBytes: 3,
	}}

	response := client.sendTCPHello(conn)

	if response.Body != "abc" {
		t.Fatalf("body = %q, want truncated body", response.Body)
	}
	if !response.BodyTruncated {
		t.Fatal("expected truncated response to be marked")
	}
}

func TestSendTCPHelloReadsCompleteBodyWhenReturningUpstreamBody(t *testing.T) {
	conn := &scriptedConn{
		readChunks: [][]byte{
			[]byte("HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\npart-"),
			[]byte("two"),
		},
	}
	client := &Client{
		id: 1,
		config: &Config{
			RequestBytes:         []byte("GET /hello HTTP/1.1\r\nHost: test\r\n\r\n"),
			ReturnUpstreamBody:   true,
			UpstreamBodyMaxBytes: 64,
		},
	}

	response := client.sendTCPHello(conn)

	if !response.Success {
		t.Fatal("expected response to be successful")
	}
	if response.Body != "part-two" {
		t.Fatalf("body = %q, want complete upstream body", response.Body)
	}
}

func TestSendTCPHelloDecodesChunkedBody(t *testing.T) {
	conn := &scriptedConn{readChunks: [][]byte{
		[]byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n"),
		[]byte("6\r\n world\r\n0\r\n\r\n"),
	}}
	client := &Client{config: &Config{
		RequestBytes:         []byte("GET /hello HTTP/1.1\r\nHost: test\r\n\r\n"),
		ReturnUpstreamBody:   true,
		UpstreamBodyMaxBytes: 64,
	}}

	response := client.sendTCPHello(conn)

	if !response.Success {
		t.Fatalf("expected response to be successful: %+v", response)
	}
	if response.Body != "hello world" {
		t.Fatalf("body = %q, want decoded chunked body", response.Body)
	}
}

func TestSendTCPHelloRejectsMalformedResponseContaining200(t *testing.T) {
	conn := &scriptedConn{readChunks: [][]byte{
		[]byte("not-http but contains 200 in the body"),
	}}
	client := &Client{config: &Config{
		RequestBytes:         []byte("GET /hello HTTP/1.1\r\nHost: test\r\n\r\n"),
		ReturnUpstreamBody:   true,
		UpstreamBodyMaxBytes: 64,
	}}

	response := client.sendTCPHello(conn)

	if response.Success {
		t.Fatalf("malformed response was accepted: %+v", response)
	}
}

func TestRunTCPClientStopsWhenContextIsCanceled(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer listener.Close()

	accepted := make(chan struct{})
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		close(accepted)
		defer conn.Close()
		_, _ = io.Copy(io.Discard, conn)
	}()

	host, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("split address failed: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan BusinessResponse, 1)
	go func() {
		client := &Client{config: &Config{TCPOperationTimeoutMS: 3000}}
		done <- client.runTCPClient(ctx, host, port, "token", "si:test")
	}()

	select {
	case <-accepted:
	case <-time.After(time.Second):
		t.Fatal("client did not connect")
	}
	cancel()

	select {
	case result := <-done:
		if result.FailureStage == "" {
			t.Fatalf("expected canceled operation to fail: %+v", result)
		}
	case <-time.After(300 * time.Millisecond):
		t.Fatal("canceled TCP request did not stop promptly")
	}
}

func TestLoadConfigSetsPerformanceDefaults(t *testing.T) {
	configFile := writeTempConfig(t, `{
		"listen_addr": ":0",
		"quic_host": "127.0.0.1",
		"quic_port": "40233",
		"tls_host": "127.0.0.1",
		"tls_port": "8002"
	}`)

	config, err := loadConfig(configFile)
	if err != nil {
		t.Fatalf("loadConfig failed: %v", err)
	}

	if config.HTTPReadHeaderTimeoutSeconds <= 0 {
		t.Fatal("expected http_read_header_timeout_s default to be set")
	}
	if config.TCPConnectTimeoutMS <= 0 {
		t.Fatal("expected tcp_connect_timeout_ms default to be set")
	}
	if config.TCPOperationTimeoutMS <= 0 {
		t.Fatal("expected tcp_operation_timeout_ms default to be set")
	}
	if config.QUICDialTimeoutMS <= 0 {
		t.Fatal("expected quic_dial_timeout_ms default to be set")
	}
	if config.QUICStreamTimeoutMS <= 0 {
		t.Fatal("expected quic_stream_timeout_ms default to be set")
	}
	if !config.ReturnUpstreamBody {
		t.Fatal("expected return_upstream_body to default to true for compatibility")
	}
	if config.UpstreamBodyMaxBytes <= 0 {
		t.Fatal("expected upstream_body_max_bytes default to be set")
	}
}

func TestLoadConfigSetsDefaultLogFile(t *testing.T) {
	configFile := writeTempConfig(t, `{
		"listen_addr": ":0",
		"quic_host": "127.0.0.1",
		"quic_port": "40233",
		"tls_host": "127.0.0.1",
		"tls_port": "8002"
	}`)

	config, err := loadConfig(configFile)
	if err != nil {
		t.Fatalf("loadConfig failed: %v", err)
	}

	if config.LogFile != "spa-test-server.log" {
		t.Fatalf("log_file = %q, want default log file", config.LogFile)
	}
	if config.LogLevel != "error" {
		t.Fatalf("log_level = %q, want error", config.LogLevel)
	}
}

func TestSetupLoggerWritesOnlyEnabledLevelsToConfiguredFile(t *testing.T) {
	logFile := t.TempDir() + "/app.log"
	closer, err := setupLogger(&Config{LogFile: logFile, LogLevel: "error"})
	if err != nil {
		t.Fatalf("setupLogger failed: %v", err)
	}
	defer slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))

	slog.Debug("debug-line")
	slog.Info("info-line")
	slog.Error("error-line")
	if err := closer.Close(); err != nil {
		t.Fatalf("close logger failed: %v", err)
	}

	data, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("failed to read log file: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "error-line") {
		t.Fatalf("log file does not contain error line: %s", data)
	}
	if strings.Contains(content, "info-line") || strings.Contains(content, "debug-line") {
		t.Fatalf("error log level wrote lower-level messages: %s", data)
	}
}

func TestSetupLoggerDebugLevelWritesAllLevels(t *testing.T) {
	logFile := t.TempDir() + "/app.log"
	closer, err := setupLogger(&Config{LogFile: logFile, LogLevel: "debug"})
	if err != nil {
		t.Fatalf("setupLogger failed: %v", err)
	}
	defer slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))

	slog.Debug("debug-line")
	slog.Info("info-line")
	slog.Error("error-line")
	if err := closer.Close(); err != nil {
		t.Fatalf("close logger failed: %v", err)
	}

	data, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("failed to read log file: %v", err)
	}
	content := string(data)
	for _, message := range []string{"debug-line", "info-line", "error-line"} {
		if !strings.Contains(content, message) {
			t.Fatalf("debug log level did not write %q: %s", message, data)
		}
	}
}

func TestSetupLoggerDoesNotWriteToStdout(t *testing.T) {
	logFile := t.TempDir() + "/app.log"
	stdoutReader, stdoutWriter, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stdout pipe failed: %v", err)
	}
	originalStdout := os.Stdout
	os.Stdout = stdoutWriter
	defer func() {
		os.Stdout = originalStdout
		stdoutReader.Close()
	}()

	closer, err := setupLogger(&Config{LogFile: logFile, LogLevel: "debug"})
	if err != nil {
		t.Fatalf("setupLogger failed: %v", err)
	}
	defer slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))

	slog.Error("file-only-line")
	if err := closer.Close(); err != nil {
		t.Fatalf("close logger failed: %v", err)
	}
	if err := stdoutWriter.Close(); err != nil {
		t.Fatalf("close stdout pipe failed: %v", err)
	}
	stdoutData, err := io.ReadAll(stdoutReader)
	if err != nil {
		t.Fatalf("read stdout failed: %v", err)
	}
	if len(stdoutData) != 0 {
		t.Fatalf("logger wrote to stdout: %q", stdoutData)
	}
}

func TestSetupLoggerUsesColumnLogFormat(t *testing.T) {
	logFile := t.TempDir() + "/app.log"
	closer, err := setupLogger(&Config{LogFile: logFile, LogLevel: "debug"})
	if err != nil {
		t.Fatalf("setupLogger failed: %v", err)
	}
	defer slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))

	slog.Error("format test", "event", "format_test", "status", 502)
	if err := closer.Close(); err != nil {
		t.Fatalf("close logger failed: %v", err)
	}

	data, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("failed to read log file: %v", err)
	}
	content := string(data)
	if strings.Contains(content, "time=") || strings.Contains(content, "level=") || strings.Contains(content, "msg=") {
		t.Fatalf("log contains slog field prefixes: %s", data)
	}
	pattern := `^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{6}\s+error\s+\S*main_test\.go:\d+\s+format test event=format_test status=502\n$`
	if !regexp.MustCompile(pattern).MatchString(content) {
		t.Fatalf("log does not match column format: %s", data)
	}
}

func TestSetupLoggerRejectsInvalidLevel(t *testing.T) {
	_, err := setupLogger(&Config{LogFile: t.TempDir() + "/app.log", LogLevel: "verbose"})
	if err == nil || !strings.Contains(err.Error(), "log_level") {
		t.Fatalf("expected invalid log_level error, got %v", err)
	}
}

func TestAsyncLogSinkDoesNotBlockWhenQueueIsFull(t *testing.T) {
	writer := newBlockingWriteCloser()
	sink := newAsyncLogSink(writer, 1)
	defer func() {
		close(writer.release)
		_ = sink.Close()
	}()

	if _, err := sink.Write([]byte("first\n")); err != nil {
		t.Fatalf("first write failed: %v", err)
	}
	select {
	case <-writer.started:
	case <-time.After(time.Second):
		t.Fatal("background logger did not start writing")
	}
	if _, err := sink.Write([]byte("second\n")); err != nil {
		t.Fatalf("second write failed: %v", err)
	}

	start := time.Now()
	if _, err := sink.Write([]byte("third\n")); err != nil {
		t.Fatalf("full queue write failed: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 50*time.Millisecond {
		t.Fatalf("full log queue blocked for %s", elapsed)
	}
	if sink.dropped.Load() == 0 {
		t.Fatal("expected full queue write to increment dropped count")
	}
}

func TestLoadConfigKeepsConfiguredResponseBodyLimit(t *testing.T) {
	configFile := writeTempConfig(t, `{
		"quic_host": "127.0.0.1",
		"quic_port": "40233",
		"tls_host": "127.0.0.1",
		"tls_port": "8002",
		"log_level": "debug",
		"return_upstream_body": false,
		"upstream_body_max_bytes": 8192
	}`)

	config, err := loadConfig(configFile)
	if err != nil {
		t.Fatalf("loadConfig failed: %v", err)
	}
	if config.UpstreamBodyMaxBytes != 8192 {
		t.Fatalf("UpstreamBodyMaxBytes = %d, want 8192", config.UpstreamBodyMaxBytes)
	}
}

func TestHandleProxyReturnsTooManyRequestsWhenLimitExceeded(t *testing.T) {
	app := NewApp(&Config{MaxProxyConcurrency: 1})
	app.proxySem <- struct{}{}

	req := httptest.NewRequest(http.MethodPost, "/proxy", strings.NewReader(`{"token_id":"token","session_id":"si:test"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	app.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected status 429, got %d with body %s", rec.Code, rec.Body.String())
	}
	var response proxyResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if response.Success {
		t.Fatal("expected concurrency limited response to be unsuccessful")
	}
	if !strings.Contains(response.Error, "too many") {
		t.Fatalf("expected too many requests error, got %q", response.Error)
	}
}

func TestHandleProxyErrorLogContainsContextWithoutFullToken(t *testing.T) {
	logFile := t.TempDir() + "/app.log"
	closer, err := setupLogger(&Config{LogFile: logFile, LogLevel: "error"})
	if err != nil {
		t.Fatalf("setupLogger failed: %v", err)
	}
	defer slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))

	app := NewApp(&Config{MaxProxyConcurrency: 1})
	app.proxySem <- struct{}{}
	fullToken := "token-secret-value-1234567890"
	req := httptest.NewRequest(http.MethodPost, "/proxy", strings.NewReader(`{"token_id":"`+fullToken+`","session_id":"si:test"}`))
	rec := httptest.NewRecorder()

	app.routes().ServeHTTP(rec, req)
	if err := closer.Close(); err != nil {
		t.Fatalf("close logger failed: %v", err)
	}

	data, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("failed to read log file: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "event=proxy_failed") || !strings.Contains(content, "status=429") || !strings.Contains(content, "session_id=si:test") {
		t.Fatalf("proxy error log is missing context: %s", data)
	}
	if strings.Contains(content, fullToken) {
		t.Fatalf("proxy error log contains full token: %s", data)
	}
}

func TestTokenPreviewNeverReturnsFullToken(t *testing.T) {
	for _, token := range []string{"short-token", "token-secret-value-1234567890"} {
		preview := tokenPreview(token)
		if preview == token || strings.Contains(preview, token) {
			t.Fatalf("tokenPreview(%q) exposed the full token: %q", token, preview)
		}
	}
}

func TestSendTCPHelloReturnsFalseForNon200Response(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	done := make(chan BusinessResponse, 1)
	go func() {
		client := &Client{id: 1, config: &Config{RequestBytes: []byte("GET /hello HTTP/1.0\r\nHost: test\r\n\r\n")}}
		done <- client.sendTCPHello(clientConn)
	}()

	request := make([]byte, 512)
	if _, err := serverConn.Read(request); err != nil {
		t.Fatalf("expected business request, got read error: %v", err)
	}
	if _, err := serverConn.Write([]byte("HTTP/1.0 500 Internal Server Error\r\n\r\n")); err != nil {
		t.Fatalf("failed to write response: %v", err)
	}

	result := <-done
	if result.Success {
		t.Fatal("sendTCPHello returned true for a non-200 response")
	}
	if result.FailureStage != "business_response" {
		t.Fatalf("FailureStage = %q, want business_response", result.FailureStage)
	}
	if !strings.Contains(result.Error, "500") {
		t.Fatalf("Error = %q, want upstream status details", result.Error)
	}
}

func TestSendTCPHelloDebugLogsUpstreamResponse(t *testing.T) {
	logFile := t.TempDir() + "/app.log"
	closer, err := setupLogger(&Config{LogFile: logFile, LogLevel: "debug"})
	if err != nil {
		t.Fatalf("setupLogger failed: %v", err)
	}
	defer slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	done := make(chan BusinessResponse, 1)
	go func() {
		client := &Client{
			id: 7,
			config: &Config{
				RequestBytes:         []byte("GET /hello HTTP/1.0\r\nHost: test\r\n\r\n"),
				ReturnUpstreamBody:   true,
				UpstreamBodyMaxBytes: 4096,
			},
		}
		done <- client.sendTCPHello(clientConn)
	}()

	request := make([]byte, 512)
	if _, err := serverConn.Read(request); err != nil {
		t.Fatalf("expected business request, got read error: %v", err)
	}
	if _, err := serverConn.Write([]byte("HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok")); err != nil {
		t.Fatalf("failed to write response: %v", err)
	}
	if result := <-done; !result.Success {
		t.Fatalf("sendTCPHello failed: %+v", result)
	}
	if err := closer.Close(); err != nil {
		t.Fatalf("close logger failed: %v", err)
	}

	data, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("failed to read log file: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "upstream_response") || !strings.Contains(content, "HTTP/1.0 200 OK") {
		t.Fatalf("debug log does not contain upstream response: %s", data)
	}
}

func TestRunTCPClientFailsWhenBusinessRequestFails(t *testing.T) {
	cert := newTestCertificate(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer listener.Close()

	serverDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()

		tlsConn := tls.Server(conn, &tls.Config{
			Certificates: []tls.Certificate{cert},
			MaxVersion:   tls.VersionTLS12,
		})
		if err := tlsConn.Handshake(); err != nil {
			serverDone <- err
			return
		}

		header := make([]byte, 160)
		if _, err := io.ReadFull(tlsConn, header); err != nil {
			serverDone <- err
			return
		}
		if got := int32(binary.LittleEndian.Uint32(header[0:4])); got != 86 {
			serverDone <- errUnexpected("server_id", got, int32(86))
			return
		}
		if got := binary.LittleEndian.Uint16(header[58:60]); got != 9091 {
			serverDone <- errUnexpected("local_port", got, uint16(9091))
			return
		}
		appName := bytes.TrimRight(header[60:160], "\x00")
		if string(appName) != "test-app" {
			serverDone <- errUnexpected("app_name", string(appName), "test-app")
			return
		}
		if _, err := tlsConn.Write(make([]byte, 5)); err != nil {
			serverDone <- err
			return
		}
		time.Sleep(10 * time.Millisecond)
		if _, err := tlsConn.Write(make([]byte, 15)); err != nil {
			serverDone <- err
			return
		}

		request := make([]byte, 512)
		if _, err := tlsConn.Read(request); err != nil {
			serverDone <- err
			return
		}
		_, err = tlsConn.Write([]byte("HTTP/1.0 500 Internal Server Error\r\n\r\n"))
		serverDone <- err
	}()

	host, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("failed to split listener address: %v", err)
	}

	client := &Client{
		id: 1,
		config: &Config{
			TLSServerName: "10.10.27.126",
			ServerID:      86,
			LocalPort:     9091,
			AppNameBytes:  []byte("test-app"),
			RequestBytes:  []byte("GET /hello HTTP/1.0\r\nHost: 10.10.27.97:9090\r\n\r\n"),
		},
	}
	if got := client.runTCPClient(context.Background(), host, port, "test-token", "si:test-session"); got.Success {
		t.Fatal("runTCPClient returned true when the business request returned non-200")
	}

	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatalf("server failed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not finish")
	}
}

func TestHelpDoesNotRequireConfig(t *testing.T) {
	if os.Getenv("TLS_TEST_RUN_MAIN") == "1" {
		os.Args = []string{"TLS-test", "--help"}
		main()
		os.Exit(0)
	}

	cmd := exec.Command(os.Args[0], "-test.run", t.Name())
	cmd.Env = append(os.Environ(), "TLS_TEST_RUN_MAIN=1")
	cmd.Dir = t.TempDir()

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("--help exited with error: %v\noutput:\n%s", err, output)
	}
	if !strings.Contains(string(output), "Usage:") {
		t.Fatalf("expected help output to contain Usage:, got:\n%s", output)
	}
}

func TestNewHTTPServerHasFileLoggerAdapter(t *testing.T) {
	server := newHTTPServer(&Config{}, http.NewServeMux())
	if server.ErrorLog == nil {
		t.Fatal("expected net/http internal errors to be routed through the service logger")
	}
}

func TestServeHTTPStopsCleanlyWhenContextIsCanceled(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	server := newHTTPServer(&Config{}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- serveHTTP(ctx, server, listener, time.Second)
	}()

	response, err := http.Get("http://" + listener.Addr().String())
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	response.Body.Close()
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("server returned shutdown error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server did not stop after context cancellation")
	}
}

func newTestCertificate(t *testing.T) tls.Certificate {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}
	return cert
}

func writeTempConfig(t *testing.T, content string) string {
	t.Helper()

	path := t.TempDir() + "/config.json"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}
	return path
}

func errUnexpected(name string, got, want interface{}) error {
	return fmt.Errorf("%s = %v, want %v", name, got, want)
}

type scriptedConn struct {
	readChunks [][]byte
	writes     [][]byte
}

func (c *scriptedConn) Read(b []byte) (int, error) {
	if len(c.readChunks) == 0 {
		return 0, io.EOF
	}
	chunk := c.readChunks[0]
	c.readChunks = c.readChunks[1:]
	n := copy(b, chunk)
	if n < len(chunk) {
		c.readChunks = append([][]byte{chunk[n:]}, c.readChunks...)
	}
	return n, nil
}

func (c *scriptedConn) Write(b []byte) (int, error) {
	c.writes = append(c.writes, append([]byte(nil), b...))
	return len(b), nil
}

func (c *scriptedConn) Close() error {
	return nil
}

func (c *scriptedConn) LocalAddr() net.Addr {
	return dummyAddr("local")
}

func (c *scriptedConn) RemoteAddr() net.Addr {
	return dummyAddr("remote")
}

func (c *scriptedConn) SetDeadline(time.Time) error {
	return nil
}

func (c *scriptedConn) SetReadDeadline(time.Time) error {
	return nil
}

func (c *scriptedConn) SetWriteDeadline(time.Time) error {
	return nil
}

type dummyAddr string

func (a dummyAddr) Network() string {
	return string(a)
}

func (a dummyAddr) String() string {
	return string(a)
}

type blockingWriteCloser struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

type shortWriter struct {
	buffer bytes.Buffer
	max    int
}

func (w *shortWriter) Write(data []byte) (int, error) {
	if len(data) > w.max {
		data = data[:w.max]
	}
	return w.buffer.Write(data)
}

func newBlockingWriteCloser() *blockingWriteCloser {
	return &blockingWriteCloser{started: make(chan struct{}), release: make(chan struct{})}
}

func (w *blockingWriteCloser) Write(p []byte) (int, error) {
	w.once.Do(func() { close(w.started) })
	<-w.release
	return len(p), nil
}

func (w *blockingWriteCloser) Close() error {
	return nil
}
