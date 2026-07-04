package main

import (
	"bytes"
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
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
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

func TestParseBusinessResponseExtractsStatusAndBody(t *testing.T) {
	response := parseBusinessResponse([]byte("HTTP/1.1 201 Created\r\nContent-Type: text/plain\r\n\r\ncreated ok"), nil)

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

func TestParseBusinessResponseOmitsBodyWhenDisabled(t *testing.T) {
	response := parseBusinessResponse([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\ncreated ok"), &Config{
		ReturnUpstreamBody: false,
	})

	if !response.Success {
		t.Fatal("expected 200 response to be successful")
	}
	if response.StatusCode != 200 {
		t.Fatalf("status code = %d", response.StatusCode)
	}
	if response.Body != "" {
		t.Fatalf("body = %q, want empty body", response.Body)
	}
	if response.Bytes == 0 {
		t.Fatal("expected byte count to be set")
	}
}

func TestParseBusinessResponseTruncatesBodyWhenLimitConfigured(t *testing.T) {
	response := parseBusinessResponse([]byte("HTTP/1.1 200 OK\r\n\r\nabcdef"), &Config{
		ReturnUpstreamBody:   true,
		UpstreamBodyMaxBytes: 3,
	})

	if response.Body != "abc" {
		t.Fatalf("body = %q, want truncated body", response.Body)
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
			ReadLimit:            64,
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

func TestSendTCPHelloReturnsFalseForNon200Response(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	done := make(chan bool, 1)
	go func() {
		client := &Client{id: 1, config: &Config{RequestBytes: []byte("GET /hello HTTP/1.0\r\nHost: test\r\n\r\n")}}
		done <- client.sendTCPHello(clientConn).Success
	}()

	request := make([]byte, 512)
	if _, err := serverConn.Read(request); err != nil {
		t.Fatalf("expected business request, got read error: %v", err)
	}
	if _, err := serverConn.Write([]byte("HTTP/1.0 500 Internal Server Error\r\n\r\n")); err != nil {
		t.Fatalf("failed to write response: %v", err)
	}

	if got := <-done; got {
		t.Fatal("sendTCPHello returned true for a non-200 response")
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
		if _, err := tlsConn.Write(make([]byte, 20)); err != nil {
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
	if got := client.runTCPClient(host, port, "test-token", "si:test-session"); got.Success {
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
