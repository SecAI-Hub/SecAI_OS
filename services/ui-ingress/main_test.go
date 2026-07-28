package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func localListener(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return listener
}

func TestProxyForwardsBidirectionally(t *testing.T) {
	upstream := localListener(t)
	defer upstream.Close()
	go func() {
		connection, err := upstream.Accept()
		if err != nil {
			return
		}
		defer connection.Close()
		request, err := bufio.NewReader(connection).ReadString('\n')
		if err == nil {
			_, _ = io.WriteString(connection, "upstream:"+request)
		}
	}()

	listener := localListener(t)
	ctx, cancel := context.WithCancel(context.Background())
	server := proxyServer{
		name:            "test",
		upstream:        upstream.Addr().String(),
		connectionLimit: 2,
	}
	done := make(chan error, 1)
	go func() {
		done <- server.serve(ctx, listener)
	}()

	client, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(client, "hello\n"); err != nil {
		t.Fatal(err)
	}
	response, err := bufio.NewReader(client).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if response != "upstream:hello\n" {
		t.Fatalf("unexpected response: %q", response)
	}
	_ = client.Close()
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestProxyRejectsInvalidConnectionLimit(t *testing.T) {
	listener := localListener(t)
	server := proxyServer{name: "test", connectionLimit: 0}
	if err := server.serve(context.Background(), listener); err == nil {
		t.Fatal("expected an invalid connection-limit error")
	}
}

func TestProxyClosesWhenUpstreamDialFails(t *testing.T) {
	listener := localListener(t)
	ctx, cancel := context.WithCancel(context.Background())
	server := proxyServer{
		name:            "test",
		upstream:        "unreachable.invalid:1",
		connectionLimit: 1,
		dialContext: func(
			context.Context,
			string,
			string,
		) (net.Conn, error) {
			return nil, fmt.Errorf("deliberate dial failure")
		},
	}
	done := make(chan error, 1)
	go func() {
		done <- server.serve(ctx, listener)
	}()

	client, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 1)
	if _, err := client.Read(buffer); err == nil {
		t.Fatal("proxy kept a client open after the upstream dial failed")
	}
	_ = client.Close()
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestCheckHealthAcceptsOnlyOKStatus(t *testing.T) {
	for _, test := range []struct {
		name    string
		status  string
		wantErr bool
	}{
		{name: "http11", status: "HTTP/1.1 200 OK\r\n", wantErr: false},
		{name: "http10", status: "HTTP/1.0 200 OK\r\n", wantErr: false},
		{name: "failure", status: "HTTP/1.1 503 Service Unavailable\r\n", wantErr: true},
		{name: "malformed", status: "not-http\r\n", wantErr: true},
		{
			name: "oversized-headers",
			status: "HTTP/1.1 200 OK\r\nX-Fill: " +
				strings.Repeat("a", maxHealthResponseBytes),
			wantErr: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			listener := localListener(t)
			defer listener.Close()
			go func() {
				connection, err := listener.Accept()
				if err != nil {
					return
				}
				defer connection.Close()
				_, _ = bufio.NewReader(connection).ReadString('\n')
				_, _ = io.WriteString(connection, test.status+"\r\n")
			}()
			err := checkHealth(listener.Addr().String())
			if (err != nil) != test.wantErr {
				t.Fatalf("checkHealth() error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}

func healthListener(t *testing.T, body string) net.Listener {
	t.Helper()
	listener := localListener(t)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		defer connection.Close()
		_, _ = bufio.NewReader(connection).ReadString('\n')
		_, _ = fmt.Fprintf(
			connection,
			"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"+
				"Content-Length: %d\r\nConnection: close\r\n\r\n%s",
			len(body),
			body,
		)
	}()
	return listener
}

func TestCheckAllHealthRequiresCurrentControlRoute(t *testing.T) {
	for _, test := range []struct {
		name        string
		controlBody string
		wantErr     bool
	}{
		{
			name:        "current",
			controlBody: `{"controller":"secai-sandbox-control","protocol_version":3}`,
			wantErr:     false,
		},
		{
			name:        "stale",
			controlBody: `{"controller":"secai-sandbox-control","protocol_version":1}`,
			wantErr:     true,
		},
		{
			name:        "wrong-service",
			controlBody: `{"status":"ok"}`,
			wantErr:     true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			ui := healthListener(t, `{"status":"ok"}`)
			defer ui.Close()
			control := healthListener(t, test.controlBody)
			defer control.Close()

			err := checkAllHealth(ui.Addr().String(), control.Addr().String())
			if (err != nil) != test.wantErr {
				t.Fatalf(
					"checkAllHealth() error = %v, wantErr %v",
					err,
					test.wantErr,
				)
			}
		})
	}
}

func TestIngressRoutesAndLimitsAreFixed(t *testing.T) {
	if uiListenAddress != "0.0.0.0:8480" || uiUpstreamAddress != "ui:8480" {
		t.Fatal("UI ingress route changed")
	}
	if controlListenAddress != "0.0.0.0:8498" ||
		controlUpstream != "host.docker.internal:8498" {
		t.Fatal("sandbox-control route changed")
	}
	if uiConnectionLimit < 1 || uiConnectionLimit > 256 {
		t.Fatal("UI connection limit is outside the reviewed bound")
	}
	if controlConnectionLimit < 1 ||
		controlConnectionLimit >= uiConnectionLimit {
		t.Fatal("control connection limit is outside the reviewed bound")
	}
	if idleTimeout <= 0 || maxConnectionLifetime <= idleTimeout {
		t.Fatal("connection timeouts are not bounded")
	}
	if strings.Contains(uiUpstreamAddress, "://") ||
		strings.Contains(controlUpstream, "://") {
		t.Fatal("raw TCP upstreams must be fixed host:port values")
	}
	if uiHealthAddress != "127.0.0.1:8480" ||
		controlHealthAddress != "127.0.0.1:8498" {
		t.Fatal("health checks do not cover both fixed relay listeners")
	}
	if controlProtocolVersion != 3 {
		t.Fatal("control health does not require the current protocol")
	}
	if maxHealthResponseBytes > 4*maxHealthBodyBytes {
		t.Fatal("health response parsing is not tightly bounded")
	}
}
