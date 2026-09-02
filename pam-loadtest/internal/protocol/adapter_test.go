package protocol

import (
	"net/url"
	"testing"
	"time"
)

func TestSSHBuildsObservedEndpointAndActiveCommand(t *testing.T) {
	o, err := SSHOptions("http://pam.test:8088", "session id", "runtime-token", 158, 33, 2*time.Second, "printf active")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(o.URL)
	if u.Scheme != "ws" || u.Path != "/sessions/session id/ssh" || u.Query().Get("cols") != "158" || u.Query().Get("rows") != "33" {
		t.Fatalf("unexpected URL %s", o.URL)
	}
	command := "printf active\n"
	if o.MessageType != 1 {
		t.Fatalf("message type=%d", o.MessageType)
	}
	if len(o.StartupPayloads) != len(command)+1 || string(o.StartupPayloads[0]) != "4" {
		t.Fatalf("startup payloads=%q", o.StartupPayloads)
	}
	for i := range command {
		if got := string(o.StartupPayloads[i+1]); got != "2"+command[i:i+1] {
			t.Fatalf("startup payload %d=%q", i+1, got)
		}
	}
	if got := string(o.Payload(1)); got != "4" {
		t.Fatalf("periodic heartbeat payload=%q", got)
	}
	if got := string(o.Payload(2)); got != "2p" {
		t.Fatalf("periodic input payload=%q", got)
	}
	if got := string(o.Payload(uint64(len(command) + 2))); got != "2p" {
		t.Fatalf("wrapped periodic input payload=%q", got)
	}
	if want := 2 * time.Second / time.Duration(len(command)); o.Interval != want {
		t.Fatalf("interval=%s want=%s", o.Interval, want)
	}
	if want := 2 * time.Second / time.Duration(len(command)); o.StartupInterval != want {
		t.Fatalf("startup interval=%s want=%s", o.StartupInterval, want)
	}
	if u.Query().Get("X-Auth-Token") != "runtime-token" || o.Headers.Get("X-Auth-Token") != "runtime-token" {
		t.Fatal("token must be supplied through the observed query and runtime header")
	}
}

func TestSSHReconnectBuildsSameEndpointWithoutRepeatingStartupCommand(t *testing.T) {
	initial, err := SSHOptions("http://pam.test:8088", "session id", "runtime-token", 158, 33, 2*time.Second, "printf active")
	if err != nil {
		t.Fatal(err)
	}
	reconnect, err := SSHReconnectOptions("http://pam.test:8088", "session id", "runtime-token", 158, 33, 2*time.Second, "printf active")
	if err != nil {
		t.Fatal(err)
	}
	if reconnect.URL != initial.URL || reconnect.MessageType != initial.MessageType || reconnect.Interval != initial.Interval {
		t.Fatalf("reconnect=%+v initial=%+v", reconnect, initial)
	}
	if len(reconnect.StartupPayloads) != 0 || reconnect.StartupInterval != 0 {
		t.Fatalf("reconnect startup=%q interval=%s", reconnect.StartupPayloads, reconnect.StartupInterval)
	}
	if reconnect.AfterDial != nil || string(reconnect.Payload(1)) != "4" || string(reconnect.Payload(2)) != "2p" {
		t.Fatalf("reconnect=%+v", reconnect)
	}
}

func TestSSHConnectionOnlyBuildsEndpointWithoutTerminalInput(t *testing.T) {
	o, err := SSHConnectionOnlyOptions("http://pam.test:8088", "session id", "runtime-token", 158, 33)
	if err != nil {
		t.Fatal(err)
	}
	if len(o.StartupPayloads) != 0 || o.StartupInterval != 0 || o.Interval != 15*time.Second || o.Payload == nil || string(o.Payload(1)) != "4" {
		t.Fatalf("connection-only options must not emit terminal input: %+v", o)
	}
}

func TestMySQLBuildsObservedEndpointAndQuery(t *testing.T) {
	o, err := MySQLOptions("https://pam.test", "db-session", "runtime-token", time.Second, "select count(*) from payload")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(o.URL)
	if u.Scheme != "wss" || u.Path != "/db-sessions/db-session/ws" {
		t.Fatalf("unexpected URL %s", o.URL)
	}
	if u.Query().Get("X-Auth-Token") != "runtime-token" || o.Headers.Get("X-Auth-Token") != "runtime-token" {
		t.Fatal("token must be supplied through the observed query and runtime header")
	}
	query := "select count(*) from payload;\n"
	if o.MessageType != 1 {
		t.Fatalf("message type=%d", o.MessageType)
	}
	if got := string(o.Payload(1)); got != "4" {
		t.Fatalf("initial payload=%q", got)
	}
	for i := range query {
		if got := string(o.Payload(uint64(i + 2))); got != "2"+query[i:i+1] {
			t.Fatalf("payload %d=%q", i+2, got)
		}
	}
	if got := string(o.Payload(uint64(len(query) + 2))); got != "2"+query[:1] {
		t.Fatalf("wrapped payload=%q", got)
	}
	if want := time.Second / time.Duration(len(query)); o.Interval != want {
		t.Fatalf("interval=%s want=%s", o.Interval, want)
	}
}
