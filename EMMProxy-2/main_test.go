package main

import (
	"bufio"
	"fmt"
	"net"
	"testing"
	"time"
)

func newTestClient(request string) *Client {
	return &Client{
		id: 1,
		config: &Config{
			HttpRequests: []string{request},
			Timeout:      time.Second,
			TestMode:     "memory",
		},
		manager: &ClientManager{},
	}
}

func servePipeResponse(t *testing.T, request string, chunks ...string) net.Conn {
	t.Helper()

	clientConn, serverConn := net.Pipe()
	go func() {
		defer serverConn.Close()

		reader := bufio.NewReader(serverConn)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				t.Errorf("failed to read request: %v", err)
				return
			}
			if line == "\r\n" {
				break
			}
		}

		for _, chunk := range chunks {
			if _, err := fmt.Fprint(serverConn, chunk); err != nil {
				return
			}
		}
	}()

	return clientConn
}

func TestSendTCPHelloFailsWhenBodyShorterThanContentLength(t *testing.T) {
	request := "GET /file HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n"
	client := newTestClient(request)
	conn := servePipeResponse(t, request, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nabc")
	defer conn.Close()

	if client.sendTCPHello(conn) {
		t.Fatal("expected incomplete body to fail")
	}
}

func TestSendTCPHelloParsesSplitResponseHeader(t *testing.T) {
	request := "GET /file HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n"
	client := newTestClient(request)
	conn := servePipeResponse(t, request,
		"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n",
		"Connection: close\r\n\r\nhello",
	)
	defer conn.Close()

	if !client.sendTCPHello(conn) {
		t.Fatal("expected split response header to succeed")
	}
}
