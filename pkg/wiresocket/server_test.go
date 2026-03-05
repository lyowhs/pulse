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

// TestAllowedPeersAccept verifies that a client whose public key is in the
// AllowedPeers whitelist can connect successfully.
func TestAllowedPeersAccept(t *testing.T) {
	clientKP, err := wiresocket.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan struct{})

	addr, kp := serverSetup(t, wiresocket.ServerConfig{
		AllowedPeers: [][32]byte{clientKP.Public},
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
		t.Fatalf("whitelisted client: Dial failed: %v", err)
	}
	defer conn.Close()

	select {
	case <-accepted:
	case <-ctx.Done():
		t.Error("timeout: OnConnect not called for whitelisted client")
	}
}

// TestAllowedPeersReject verifies that a client whose public key is not in the
// AllowedPeers whitelist is silently rejected: Dial must fail and OnConnect
// must not be called.
func TestAllowedPeersReject(t *testing.T) {
	allowedKP, _ := wiresocket.GenerateKeypair()
	var onConnectCalled atomic.Bool

	addr, kp := serverSetup(t, wiresocket.ServerConfig{
		AllowedPeers: [][32]byte{allowedKP.Public},
		OnConnect: func(conn *wiresocket.Conn) {
			onConnectCalled.Store(true)
			<-conn.Done()
		},
	})

	// Dial with a fresh ephemeral key (not in the whitelist).
	dialCtx, dialCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer dialCancel()
	_, err := wiresocket.Dial(dialCtx, addr, wiresocket.DialConfig{
		ServerPublicKey:  kp.Public,
		HandshakeTimeout: 200 * time.Millisecond,
		MaxRetries:       1,
	})
	if err == nil {
		t.Error("non-whitelisted client: Dial succeeded, want error")
	}
	if onConnectCalled.Load() {
		t.Error("OnConnect was called for a non-whitelisted client")
	}
}

// TestAllowedPeersMultiple verifies that the whitelist accepts any key in the
// list and rejects keys not in the list.
func TestAllowedPeersMultiple(t *testing.T) {
	kpA, _ := wiresocket.GenerateKeypair()
	kpB, _ := wiresocket.GenerateKeypair()
	kpC, _ := wiresocket.GenerateKeypair() // not in list

	var accepted atomic.Int64

	addr, kp := serverSetup(t, wiresocket.ServerConfig{
		AllowedPeers: [][32]byte{kpA.Public, kpB.Public},
		OnConnect: func(conn *wiresocket.Conn) {
			accepted.Add(1)
			<-conn.Done()
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// kpA and kpB should both connect.
	for _, ckp := range []wiresocket.Keypair{kpA, kpB} {
		conn, err := wiresocket.Dial(ctx, addr, wiresocket.DialConfig{
			ServerPublicKey: kp.Public,
			PrivateKey:      ckp.Private,
		})
		if err != nil {
			t.Fatalf("whitelisted client: Dial failed: %v", err)
		}
		defer conn.Close()
	}

	// Wait for both to be accepted.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && accepted.Load() < 2 {
		time.Sleep(10 * time.Millisecond)
	}
	if got := accepted.Load(); got != 2 {
		t.Errorf("accepted %d clients, want 2", got)
	}

	// kpC should be rejected.
	dialCtx, dialCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer dialCancel()
	_, err := wiresocket.Dial(dialCtx, addr, wiresocket.DialConfig{
		ServerPublicKey:  kp.Public,
		PrivateKey:       kpC.Private,
		HandshakeTimeout: 200 * time.Millisecond,
		MaxRetries:       1,
	})
	if err == nil {
		t.Error("non-whitelisted client C: Dial succeeded, want error")
	}
}

// TestAllowedPeersAndAuthenticate verifies that both AllowedPeers and
// Authenticate are enforced independently: a client must pass both checks.
func TestAllowedPeersAndAuthenticate(t *testing.T) {
	kpAllowed, _ := wiresocket.GenerateKeypair()
	var onConnectCalled atomic.Bool

	// Whitelist contains kpAllowed, but Authenticate always rejects.
	addr, kp := serverSetup(t, wiresocket.ServerConfig{
		AllowedPeers: [][32]byte{kpAllowed.Public},
		Authenticate: func(_ [32]byte) bool { return false },
		OnConnect: func(conn *wiresocket.Conn) {
			onConnectCalled.Store(true)
			<-conn.Done()
		},
	})

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer dialCancel()
	_, err := wiresocket.Dial(dialCtx, addr, wiresocket.DialConfig{
		ServerPublicKey:  kp.Public,
		PrivateKey:       kpAllowed.Private,
		HandshakeTimeout: 200 * time.Millisecond,
		MaxRetries:       1,
	})
	if err == nil {
		t.Error("client passed AllowedPeers but blocked by Authenticate: Dial should fail")
	}
	if onConnectCalled.Load() {
		t.Error("OnConnect called despite Authenticate returning false")
	}
}

// TestAddRemovePeers verifies that AddPeer and RemovePeer mutate the whitelist
// at runtime and that Peers returns an accurate snapshot.
func TestAddRemovePeers(t *testing.T) {
	_, _, srv := serverSetupWithSrv(t, wiresocket.ServerConfig{
		OnConnect: func(conn *wiresocket.Conn) { <-conn.Done() },
	})

	kpA, _ := wiresocket.GenerateKeypair()
	kpB, _ := wiresocket.GenerateKeypair()

	if got := srv.Peers(); len(got) != 0 {
		t.Fatalf("Peers before any AddPeer: got %d, want 0", len(got))
	}

	srv.AddPeer(kpA.Public)
	srv.AddPeer(kpB.Public)

	peers := srv.Peers()
	if len(peers) != 2 {
		t.Fatalf("Peers after 2 AddPeer: got %d, want 2", len(peers))
	}

	// AddPeer is idempotent.
	srv.AddPeer(kpA.Public)
	if got := srv.Peers(); len(got) != 2 {
		t.Errorf("Peers after duplicate AddPeer: got %d, want 2", len(got))
	}

	// RemovePeer returns false for unknown key.
	kpC, _ := wiresocket.GenerateKeypair()
	if srv.RemovePeer(kpC.Public) {
		t.Error("RemovePeer unknown key: want false, got true")
	}

	// RemovePeer returns true and shrinks the list.
	if !srv.RemovePeer(kpA.Public) {
		t.Error("RemovePeer known key: want true, got false")
	}
	if got := srv.Peers(); len(got) != 1 {
		t.Fatalf("Peers after RemovePeer: got %d, want 1", len(got))
	}
	if srv.Peers()[0] != kpB.Public {
		t.Error("remaining peer after RemovePeer is not kpB")
	}

	// Removing the last peer disables the whitelist.
	srv.RemovePeer(kpB.Public)
	if got := srv.Peers(); len(got) != 0 {
		t.Errorf("Peers after removing all: got %d, want 0", len(got))
	}
}

// TestAddPeerEnablesWhitelist verifies that adding a peer at runtime restricts
// new connections to whitelisted keys only, and removing it opens the server again.
func TestAddPeerEnablesWhitelist(t *testing.T) {
	connected := make(chan struct{}, 4)

	addr, kp, srv := serverSetupWithSrv(t, wiresocket.ServerConfig{
		OnConnect: func(conn *wiresocket.Conn) {
			connected <- struct{}{}
			<-conn.Done()
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// No whitelist: any client can connect.
	kpAny, _ := wiresocket.GenerateKeypair()
	connA, err := wiresocket.Dial(ctx, addr, wiresocket.DialConfig{
		ServerPublicKey: kp.Public,
		PrivateKey:      kpAny.Private,
	})
	if err != nil {
		t.Fatalf("pre-whitelist Dial failed: %v", err)
	}
	defer connA.Close()

	select {
	case <-connected:
	case <-ctx.Done():
		t.Fatal("timeout waiting for pre-whitelist connection")
	}

	// Enable whitelist with a specific key.
	kpAllowed, _ := wiresocket.GenerateKeypair()
	srv.AddPeer(kpAllowed.Public)

	// Non-whitelisted client must be rejected.
	rejectCtx, rejectCancel := context.WithTimeout(ctx, 2*time.Second)
	defer rejectCancel()
	kpOther, _ := wiresocket.GenerateKeypair()
	_, err = wiresocket.Dial(rejectCtx, addr, wiresocket.DialConfig{
		ServerPublicKey:  kp.Public,
		PrivateKey:       kpOther.Private,
		HandshakeTimeout: 200 * time.Millisecond,
		MaxRetries:       1,
	})
	if err == nil {
		t.Error("non-whitelisted client after AddPeer: Dial should fail")
	}

	// Whitelisted client must connect.
	connB, err := wiresocket.Dial(ctx, addr, wiresocket.DialConfig{
		ServerPublicKey: kp.Public,
		PrivateKey:      kpAllowed.Private,
	})
	if err != nil {
		t.Fatalf("whitelisted client after AddPeer: Dial failed: %v", err)
	}
	defer connB.Close()

	select {
	case <-connected:
	case <-ctx.Done():
		t.Fatal("timeout waiting for whitelisted connection")
	}

	// Remove the peer — whitelist becomes empty, all clients accepted again.
	srv.RemovePeer(kpAllowed.Public)

	connC, err := wiresocket.Dial(ctx, addr, wiresocket.DialConfig{
		ServerPublicKey: kp.Public,
		PrivateKey:      kpOther.Private,
	})
	if err != nil {
		t.Fatalf("after RemovePeer (empty whitelist): Dial failed: %v", err)
	}
	defer connC.Close()

	select {
	case <-connected:
	case <-ctx.Done():
		t.Fatal("timeout waiting for post-whitelist connection")
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
