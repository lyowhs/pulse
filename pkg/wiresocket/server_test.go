package wiresocket_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"example.com/pulse/pulse/pkg/wiresocket"
)

// TestAuthenticateAccept verifies that a client whose static public key is
// approved by the Authenticate callback can successfully connect.
func TestAuthenticateAccept(t *testing.T) {
	clientKP, err := wiresocket.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan struct{})

	addr, kp := serverSetup(t, wiresocket.ServerConfig{
		Authenticate: func(pub [32]byte) bool { return pub == clientKP.Public },
		OnConnect: func(conn *wiresocket.Conn) {
			close(accepted)
			<-conn.Done()
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := wiresocket.Dial(ctx, addr, wiresocket.DialConfig{
		ServerPublicKey: kp.Public,
		PrivateKey:      clientKP.Private,
	})
	if err != nil {
		t.Fatalf("accepted client: Dial failed: %v", err)
	}
	defer conn.Close()

	select {
	case <-accepted:
	case <-ctx.Done():
		t.Error("timeout: OnConnect not called for accepted client")
	}
}

// TestAuthenticateReject verifies that a client with an unrecognised public
// key is silently rejected: Dial must fail and OnConnect must not be called.
func TestAuthenticateReject(t *testing.T) {
	allowedKP, _ := wiresocket.GenerateKeypair()
	var onConnectCalled atomic.Bool

	addr, kp := serverSetup(t, wiresocket.ServerConfig{
		Authenticate: func(pub [32]byte) bool { return pub == allowedKP.Public },
		OnConnect: func(conn *wiresocket.Conn) {
			onConnectCalled.Store(true)
			<-conn.Done()
		},
	})

	// Use a fresh ephemeral key (not the allowed one).
	dialCtx, dialCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer dialCancel()
	_, err := wiresocket.Dial(dialCtx, addr, wiresocket.DialConfig{
		ServerPublicKey:  kp.Public,
		HandshakeTimeout: 200 * time.Millisecond,
		MaxRetries:       1,
	})
	if err == nil {
		t.Error("rejected client: Dial succeeded, want error")
	}
	if onConnectCalled.Load() {
		t.Error("OnConnect was called for rejected client")
	}
}

// TestActiveSessions verifies that ActiveSessions increments when clients
// connect and decrements when they disconnect.
func TestActiveSessions(t *testing.T) {
	const N = 5

	addr, kp, srv := serverSetupWithSrv(t, wiresocket.ServerConfig{
		OnConnect: func(conn *wiresocket.Conn) { <-conn.Done() },
	})

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer dialCancel()

	conns := make([]*wiresocket.Conn, N)
	for i := range conns {
		var err error
		conns[i], err = wiresocket.Dial(dialCtx, addr, wiresocket.DialConfig{
			ServerPublicKey: kp.Public,
		})
		if err != nil {
			t.Fatalf("Dial[%d]: %v", i, err)
		}
	}

	// Wait for all sessions to register.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && srv.ActiveSessions() < int64(N) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := srv.ActiveSessions(); got != int64(N) {
		t.Errorf("ActiveSessions after %d connects: got %d, want %d", N, got, N)
	}

	// Close half of them.
	for i := 0; i < N/2; i++ {
		conns[i].Close()
	}

	// Wait for sessions to be GC'd.
	want := int64(N - N/2)
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && srv.ActiveSessions() != want {
		time.Sleep(25 * time.Millisecond)
	}
	if got := srv.ActiveSessions(); got != want {
		t.Errorf("ActiveSessions after %d closes: got %d, want %d", N/2, got, want)
	}

	// Clean up.
	for i := N / 2; i < N; i++ {
		conns[i].Close()
	}
}
