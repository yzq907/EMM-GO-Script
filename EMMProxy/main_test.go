package main

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
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
