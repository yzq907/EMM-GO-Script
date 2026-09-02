package protocol

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"pam-loadtest/internal/transport"
)

func websocketBase(baseURL string) (*url.URL, error) {
	u, err := url.Parse(baseURL)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("invalid PAM URL")
	}
	switch u.Scheme {
	case "http":
		u.Scheme = "ws"
	case "https":
		u.Scheme = "wss"
	default:
		return nil, fmt.Errorf("invalid PAM URL scheme")
	}
	return u, nil
}

func runtimeHeaders(token string) http.Header { return http.Header{"X-Auth-Token": {token}} }

func terminalInput(interval time.Duration, input string) (time.Duration, func(uint64) []byte) {
	bytes := []byte(input)
	keyInterval := interval / time.Duration(len(bytes))
	if keyInterval < time.Millisecond {
		keyInterval = time.Millisecond
	}
	return keyInterval, func(sequence uint64) []byte {
		if sequence <= 1 {
			return []byte("4")
		}
		index := (sequence - 2) % uint64(len(bytes))
		return []byte{'2', bytes[index]}
	}
}

func terminalStartup(interval time.Duration, input string) (time.Duration, [][]byte) {
	bytes := []byte(input)
	keyInterval := interval / time.Duration(len(bytes))
	if keyInterval < time.Millisecond {
		keyInterval = time.Millisecond
	}
	payloads := make([][]byte, 0, len(bytes)+1)
	payloads = append(payloads, []byte("4"))
	for _, value := range bytes {
		payloads = append(payloads, []byte{'2', value})
	}
	return keyInterval, payloads
}

func SSHOptions(baseURL, sessionID, token string, cols, rows int, interval time.Duration, command string) (transport.WebSocketOptions, error) {
	u, err := websocketBase(baseURL)
	if err != nil {
		return transport.WebSocketOptions{}, err
	}
	u.Path = "/sessions/" + sessionID + "/ssh"
	u.RawQuery = url.Values{"cols": {strconv.Itoa(cols)}, "rows": {strconv.Itoa(rows)}, "X-Auth-Token": {token}}.Encode()
	command = strings.TrimRight(command, "\r\n") + "\n"
	startupInterval, startupPayloads := terminalStartup(interval, command)
	activityInterval, activityPayload := terminalInput(interval, command)
	return transport.WebSocketOptions{URL: u.String(), Headers: runtimeHeaders(token), Interval: activityInterval, Payload: activityPayload, StartupPayloads: startupPayloads, StartupInterval: startupInterval, MessageType: websocket.TextMessage, DialTimeout: 60 * time.Second}, nil
}

// SSHConnectionOnlyOptions opens the PAM SSH transport without writing terminal
// startup commands or terminal input. The periodic "4" frame is the minimum
// PAM transport keepalive required to prevent its idle timeout; it carries no
// shell command or user business data.
func SSHConnectionOnlyOptions(baseURL, sessionID, token string, cols, rows int) (transport.WebSocketOptions, error) {
	u, err := websocketBase(baseURL)
	if err != nil {
		return transport.WebSocketOptions{}, err
	}
	u.Path = "/sessions/" + sessionID + "/ssh"
	u.RawQuery = url.Values{"cols": {strconv.Itoa(cols)}, "rows": {strconv.Itoa(rows)}, "X-Auth-Token": {token}}.Encode()
	return transport.WebSocketOptions{URL: u.String(), Headers: runtimeHeaders(token), Interval: 15 * time.Second, Payload: func(uint64) []byte { return []byte("4") }, MessageType: websocket.TextMessage, DialTimeout: 60 * time.Second}, nil
}

func SSHReconnectOptions(baseURL, sessionID, token string, cols, rows int, interval time.Duration, command string) (transport.WebSocketOptions, error) {
	u, err := websocketBase(baseURL)
	if err != nil {
		return transport.WebSocketOptions{}, err
	}
	u.Path = "/sessions/" + sessionID + "/ssh"
	u.RawQuery = url.Values{"cols": {strconv.Itoa(cols)}, "rows": {strconv.Itoa(rows)}, "X-Auth-Token": {token}}.Encode()
	command = strings.TrimRight(command, "\r\n") + "\n"
	activityInterval, activityPayload := terminalInput(interval, command)
	return transport.WebSocketOptions{URL: u.String(), Headers: runtimeHeaders(token), Interval: activityInterval, Payload: activityPayload, MessageType: websocket.TextMessage, DialTimeout: 60 * time.Second}, nil
}

func MySQLOptions(baseURL, sessionID, token string, interval time.Duration, query string) (transport.WebSocketOptions, error) {
	u, err := websocketBase(baseURL)
	if err != nil {
		return transport.WebSocketOptions{}, err
	}
	u.Path = "/db-sessions/" + sessionID + "/ws"
	u.RawQuery = url.Values{"X-Auth-Token": {token}}.Encode()
	query = strings.TrimSpace(query)
	query = strings.TrimSuffix(query, ";") + ";\n"
	keyInterval, payload := terminalInput(interval, query)
	return transport.WebSocketOptions{URL: u.String(), Headers: runtimeHeaders(token), Interval: keyInterval, Payload: payload, MessageType: websocket.TextMessage}, nil
}
