package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

const (
	uiListenAddress      = "0.0.0.0:8480"
	uiUpstreamAddress    = "ui:8480"
	controlListenAddress = "0.0.0.0:8498"
	controlUpstream      = "host.docker.internal:8498"
	uiHealthAddress      = "127.0.0.1:8480"
	controlHealthAddress = "127.0.0.1:8498"

	uiConnectionLimit      = 128
	controlConnectionLimit = 16
	dialTimeout            = 5 * time.Second
	idleTimeout            = 2 * time.Minute
	maxConnectionLifetime  = 30 * time.Minute
	shutdownTimeout        = 10 * time.Second
	healthTimeout          = 2 * time.Second
	maxHealthBodyBytes     = 4096
	maxHealthResponseBytes = 16384
	controlProtocolVersion = 3
)

type proxyServer struct {
	name            string
	listenAddress   string
	upstream        string
	connectionLimit int
	dialContext     func(context.Context, string, string) (net.Conn, error)
}

type idleConn struct {
	net.Conn
	timeout time.Duration
}

func (connection *idleConn) Read(buffer []byte) (int, error) {
	if err := connection.SetReadDeadline(time.Now().Add(connection.timeout)); err != nil {
		return 0, err
	}
	return connection.Conn.Read(buffer)
}

func (connection *idleConn) Write(buffer []byte) (int, error) {
	if err := connection.SetWriteDeadline(time.Now().Add(connection.timeout)); err != nil {
		return 0, err
	}
	return connection.Conn.Write(buffer)
}

func (connection *idleConn) CloseWrite() error {
	if closer, ok := connection.Conn.(interface{ CloseWrite() error }); ok {
		return closer.CloseWrite()
	}
	return connection.Conn.Close()
}

func defaultDialContext(ctx context.Context, network string, address string) (net.Conn, error) {
	dialer := net.Dialer{Timeout: dialTimeout}
	return dialer.DialContext(ctx, network, address)
}

func (server proxyServer) run(ctx context.Context) error {
	listener, err := net.Listen("tcp", server.listenAddress)
	if err != nil {
		return fmt.Errorf("%s listen: %w", server.name, err)
	}
	return server.serve(ctx, listener)
}

func (server proxyServer) serve(ctx context.Context, listener net.Listener) error {
	if server.connectionLimit < 1 {
		_ = listener.Close()
		return fmt.Errorf("%s connection limit is invalid", server.name)
	}
	if server.dialContext == nil {
		server.dialContext = defaultDialContext
	}

	slots := make(chan struct{}, server.connectionLimit)
	var connections sync.WaitGroup
	stopAccepting := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = listener.Close()
		case <-stopAccepting:
		}
	}()
	defer close(stopAccepting)

	for {
		client, acceptErr := listener.Accept()
		if acceptErr != nil {
			if ctx.Err() != nil || errors.Is(acceptErr, net.ErrClosed) {
				break
			}
			var temporary interface{ Temporary() bool }
			if errors.As(acceptErr, &temporary) && temporary.Temporary() {
				continue
			}
			return fmt.Errorf("%s accept: %w", server.name, acceptErr)
		}

		select {
		case slots <- struct{}{}:
			connections.Add(1)
			go func() {
				defer connections.Done()
				defer func() { <-slots }()
				server.proxy(ctx, client)
			}()
		default:
			_ = client.Close()
		}
	}

	waited := make(chan struct{})
	go func() {
		connections.Wait()
		close(waited)
	}()
	select {
	case <-waited:
	case <-time.After(shutdownTimeout):
	}
	return nil
}

func (server proxyServer) proxy(ctx context.Context, client net.Conn) {
	defer client.Close()
	upstream, err := server.dialContext(ctx, "tcp", server.upstream)
	if err != nil {
		return
	}
	defer upstream.Close()

	lifetime := time.AfterFunc(maxConnectionLifetime, func() {
		_ = client.Close()
		_ = upstream.Close()
	})
	defer lifetime.Stop()

	clientWithTimeout := &idleConn{Conn: client, timeout: idleTimeout}
	upstreamWithTimeout := &idleConn{Conn: upstream, timeout: idleTimeout}
	var copies sync.WaitGroup
	copies.Add(2)
	go copyAndHalfClose(upstreamWithTimeout, clientWithTimeout, &copies)
	go copyAndHalfClose(clientWithTimeout, upstreamWithTimeout, &copies)
	copies.Wait()
}

func copyAndHalfClose(destination net.Conn, source net.Conn, group *sync.WaitGroup) {
	defer group.Done()
	_, _ = io.Copy(destination, source)
	if closer, ok := destination.(interface{ CloseWrite() error }); ok {
		_ = closer.CloseWrite()
	}
}

func readHealth(address string) ([]byte, error) {
	connection, err := net.DialTimeout("tcp", address, healthTimeout)
	if err != nil {
		return nil, fmt.Errorf("health dial: %w", err)
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(healthTimeout)); err != nil {
		return nil, fmt.Errorf("health deadline: %w", err)
	}
	if _, err := io.WriteString(
		connection,
		"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
	); err != nil {
		return nil, fmt.Errorf("health request: %w", err)
	}
	response, err := http.ReadResponse(
		bufio.NewReaderSize(
			io.LimitReader(connection, maxHealthResponseBytes),
			maxHealthBodyBytes,
		),
		&http.Request{Method: http.MethodGet},
	)
	if err != nil {
		return nil, fmt.Errorf("health response: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unhealthy upstream status: %q", response.Status)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxHealthBodyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("health body: %w", err)
	}
	if len(body) > maxHealthBodyBytes {
		return nil, errors.New("health body exceeds the fixed limit")
	}
	return body, nil
}

func checkHealth(address string) error {
	_, err := readHealth(address)
	return err
}

func checkControlHealth(address string) error {
	body, err := readHealth(address)
	if err != nil {
		return err
	}
	var payload struct {
		Controller      string `json:"controller"`
		ProtocolVersion int    `json:"protocol_version"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return fmt.Errorf("control health JSON: %w", err)
	}
	if payload.Controller != "secai-sandbox-control" ||
		payload.ProtocolVersion != controlProtocolVersion {
		return errors.New("control relay reached an unexpected controller")
	}
	return nil
}

func checkAllHealth(uiAddress string, controlAddress string) error {
	checks := []struct {
		name  string
		check func(string) error
		value string
	}{
		{name: "UI relay", check: checkHealth, value: uiAddress},
		{name: "control relay", check: checkControlHealth, value: controlAddress},
	}
	results := make(chan error, len(checks))
	for _, configured := range checks {
		check := configured
		go func() {
			if err := check.check(check.value); err != nil {
				results <- fmt.Errorf("%s: %w", check.name, err)
				return
			}
			results <- nil
		}()
	}
	for range checks {
		if err := <-results; err != nil {
			return err
		}
	}
	return nil
}

func run() error {
	if len(os.Args) == 2 && os.Args[1] == "healthcheck" {
		return checkAllHealth(uiHealthAddress, controlHealthAddress)
	}
	if len(os.Args) != 1 {
		return errors.New("ui-ingress accepts only the healthcheck subcommand")
	}

	ctx, stop := signal.NotifyContext(
		context.Background(),
		syscall.SIGINT,
		syscall.SIGTERM,
	)
	defer stop()

	servers := []proxyServer{
		{
			name:            "ui",
			listenAddress:   uiListenAddress,
			upstream:        uiUpstreamAddress,
			connectionLimit: uiConnectionLimit,
		},
		{
			name:            "sandbox-control",
			listenAddress:   controlListenAddress,
			upstream:        controlUpstream,
			connectionLimit: controlConnectionLimit,
		},
	}

	errs := make(chan error, len(servers))
	for _, configured := range servers {
		server := configured
		go func() {
			errs <- server.run(ctx)
		}()
	}

	for range servers {
		err := <-errs
		if err != nil {
			stop()
			return err
		}
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		log.Printf("ui-ingress: %v", err)
		os.Exit(1)
	}
}
