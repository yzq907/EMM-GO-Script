package main

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadSessionIDsTrimsBOMAndWhitespace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session_id.csv")
	content := []byte("\xef\xbb\xbfsession_id\r\n si:first \r\n\r\nsi:second\r\n")
	if err := os.WriteFile(path, content, 0644); err != nil {
		t.Fatalf("write csv: %v", err)
	}

	sessionIDs, err := loadSessionIDs(path)
	if err != nil {
		t.Fatalf("loadSessionIDs returned error: %v", err)
	}

	want := []string{"si:first", "si:second"}
	if len(sessionIDs) != len(want) {
		t.Fatalf("len(sessionIDs) = %d, want %d: %#v", len(sessionIDs), len(want), sessionIDs)
	}
	for i := range want {
		if sessionIDs[i] != want[i] {
			t.Fatalf("sessionIDs[%d] = %q, want %q", i, sessionIDs[i], want[i])
		}
	}
}

func TestLoadSessionIDsRequiresSessionIDColumn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session_id.csv")
	if err := os.WriteFile(path, []byte("sid\nsi:first\n"), 0644); err != nil {
		t.Fatalf("write csv: %v", err)
	}

	if _, err := loadSessionIDs(path); err == nil {
		t.Fatal("loadSessionIDs returned nil error, want missing session_id error")
	}
}

func TestTcpInitHeaderMarshalIntoMatchesBinaryLayout(t *testing.T) {
	var header TcpInitHeader
	header.ServerID = 86
	copy(header.SessionID[:], []byte("si:123"))
	header.UDPSynAck = 1
	header.DataLen = 160
	header.ProtoType = 1
	header.Version = 1
	header.LocalPort = 9090
	copy(header.AppName[:], []byte("test"))

	buf := make([]byte, tcpInitHeaderSize)
	n := header.MarshalInto(buf)
	if n != tcpInitHeaderSize {
		t.Fatalf("MarshalInto wrote %d bytes, want %d", n, tcpInitHeaderSize)
	}

	if got := binary.LittleEndian.Uint32(buf[0:4]); got != uint32(header.ServerID) {
		t.Fatalf("server id = %d, want %d", got, header.ServerID)
	}
	if got := string(bytes.TrimRight(buf[4:44], "\x00")); got != "si:123" {
		t.Fatalf("session id = %q, want si:123", got)
	}
	if got := binary.LittleEndian.Uint32(buf[48:52]); got != header.DataLen {
		t.Fatalf("data len = %d, want %d", got, header.DataLen)
	}
	if got := binary.LittleEndian.Uint16(buf[58:60]); got != header.LocalPort {
		t.Fatalf("local port = %d, want %d", got, header.LocalPort)
	}
	if got := string(bytes.TrimRight(buf[60:160], "\x00")); got != "test" {
		t.Fatalf("app name = %q, want test", got)
	}
}

func TestBuildRequestBytesKeepsDefaultGETBehavior(t *testing.T) {
	config := &Config{
		RequestHost: "127.0.0.1",
		RequestPort: "8090",
		RequestPath: "/status?id=123",
	}

	request, err := buildRequestBytes(config)
	if err != nil {
		t.Fatalf("buildRequestBytes returned error: %v", err)
	}

	got := string(request)
	want := "GET /status?id=123 HTTP/1.1\r\n" +
		"Host: 127.0.0.1:8090\r\n" +
		"User-Agent: curl/7.68.0\r\n" +
		"Accept: */*\r\n" +
		"Connection: close\r\n" +
		"\r\n"
	if got != want {
		t.Fatalf("request = %q, want %q", got, want)
	}
}

func TestBuildRequestBytesSupportsPostBodyAndHeaders(t *testing.T) {
	config := &Config{
		RequestHost:   "api.example.com",
		RequestPort:   "443",
		RequestMethod: "POST",
		RequestPath:   "/api/test",
		RequestHeaders: map[string]string{
			"Content-Type":   "application/json",
			"Authorization":  "Bearer token",
			"Content-Length": "999",
		},
		RequestBody: `{"id":123}`,
	}

	request, err := buildRequestBytes(config)
	if err != nil {
		t.Fatalf("buildRequestBytes returned error: %v", err)
	}

	got := string(request)
	for _, want := range []string{
		"POST /api/test HTTP/1.1\r\n",
		"Host: api.example.com:443\r\n",
		"Content-Type: application/json\r\n",
		"Authorization: Bearer token\r\n",
		"Content-Length: 10\r\n",
		"\r\n{\"id\":123}",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("request missing %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "Content-Length: 999") {
		t.Fatalf("request used configured Content-Length instead of computed length:\n%s", got)
	}
}

func TestBuildRequestBytesAllowsHostHeaderOverride(t *testing.T) {
	config := &Config{
		RequestHost: "10.0.0.1",
		RequestPort: "8080",
		RequestPath: "/status",
		RequestHeaders: map[string]string{
			"Host": "custom.example.com",
		},
	}

	request, err := buildRequestBytes(config)
	if err != nil {
		t.Fatalf("buildRequestBytes returned error: %v", err)
	}

	got := string(request)
	if !strings.Contains(got, "Host: custom.example.com\r\n") {
		t.Fatalf("request did not use custom Host:\n%s", got)
	}
	if strings.Contains(got, "Host: 10.0.0.1:8080") {
		t.Fatalf("request included default Host despite custom Host:\n%s", got)
	}
}

func TestBuildRequestBytesUsesRawRequestWhenEnabled(t *testing.T) {
	config := &Config{
		UseRawRequest: true,
		RawRequest:    "PATCH /raw HTTP/1.1\r\nHost: raw.example.com\r\n\r\nbody",
	}

	request, err := buildRequestBytes(config)
	if err != nil {
		t.Fatalf("buildRequestBytes returned error: %v", err)
	}
	if got := string(request); got != config.RawRequest {
		t.Fatalf("request = %q, want raw request %q", got, config.RawRequest)
	}
}
