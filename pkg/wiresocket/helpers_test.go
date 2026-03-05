package wiresocket_test

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"example.com/pulse/pulse/pkg/wiresocket"
)

// freePort finds an available UDP port by briefly binding one.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	port := l.LocalAddr().(*net.UDPAddr).Port
	l.Close()
	return port
}

// serverSetup starts a server with the given config, augmented with a freshly
// generated keypair and a free-port address.  The server is automatically
// stopped when the test ends.
func serverSetup(t *testing.T, cfg wiresocket.ServerConfig) (addr string, kp wiresocket.Keypair) {
	t.Helper()
	var err error
	kp, err = wiresocket.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	cfg.PrivateKey = kp.Private
	if cfg.Addr == "" {
		cfg.Addr = fmt.Sprintf("127.0.0.1:%d", freePort(t))
	}
	srv, err := wiresocket.NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go srv.Serve(ctx)
	time.Sleep(50 * time.Millisecond) // allow the goroutine to bind
	return cfg.Addr, kp
}

// serverSetupWithSrv is like serverSetup but also returns the *wiresocket.Server
// for tests that need to inspect server state (e.g. ActiveSessions).
func serverSetupWithSrv(t *testing.T, cfg wiresocket.ServerConfig) (addr string, kp wiresocket.Keypair, srv *wiresocket.Server) {
	t.Helper()
	var err error
	kp, err = wiresocket.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	cfg.PrivateKey = kp.Private
	if cfg.Addr == "" {
		cfg.Addr = fmt.Sprintf("127.0.0.1:%d", freePort(t))
	}
	srv, err = wiresocket.NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go srv.Serve(ctx)
	time.Sleep(50 * time.Millisecond)
	return cfg.Addr, kp, srv
}

// mustDial dials addr with the given keypair and optional DialConfig.
// The connection is automatically closed when the test ends.
func mustDial(t *testing.T, ctx context.Context, addr string, kp wiresocket.Keypair, extra ...wiresocket.DialConfig) *wiresocket.Conn {
	t.Helper()
	var dc wiresocket.DialConfig
	if len(extra) > 0 {
		dc = extra[0]
	}
	dc.ServerPublicKey = kp.Public
	conn, err := wiresocket.Dial(ctx, addr, dc)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}
