package wiresocket_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"example.com/pulse/pulse/pkg/wiresocket"
)

// TestRekeyPersistentConnRotatesSession verifies that a persistent connection
// automatically establishes a new session (rekey) when RekeyAfterTime elapses.
//
// The test uses a short RekeyAfterTime so the rekey fires within milliseconds.
// It checks that:
//  1. The server's OnConnect fires twice (initial + rekey).
//  2. The client's LocalIndex changes after the rekey.
//  3. Send and Recv work correctly both before and after the rekey.
func TestRekeyPersistentConnRotatesSession(t *testing.T) {
	var connects atomic.Int32
	received := make(chan uint8, 8)

	addr, kp := serverSetup(t, wiresocket.ServerConfig{
		OnConnect: func(conn *wiresocket.Conn) {
			connects.Add(1)
			for {
				e, err := conn.Recv(context.Background())
				if err != nil {
					return
				}
				received <- e.Type
				conn.Send(context.Background(), &wiresocket.Event{Type: e.Type + 10})
			}
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := wiresocket.Dial(ctx, addr, wiresocket.DialConfig{
		ServerPublicKey: kp.Public,
		ReconnectMin:    20 * time.Millisecond,
		ReconnectMax:    100 * time.Millisecond,
		RekeyAfterTime:  150 * time.Millisecond,
		// Use a session timeout longer than the rekey window so the server
		// session does not expire before the new handshake completes.
		SessionTimeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Pre-rekey: send and receive one event.
	if err := conn.Send(ctx, &wiresocket.Event{Type: 1}); err != nil {
		t.Fatalf("pre-rekey Send: %v", err)
	}
	e, err := conn.Recv(ctx)
	if err != nil {
		t.Fatalf("pre-rekey Recv: %v", err)
	}
	if e.Type != 11 {
		t.Errorf("pre-rekey echo: got type %d, want 11", e.Type)
	}

	originalIndex := conn.LocalIndex()

	// Wait for the rekey to complete: the server's OnConnect fires a second
	// time and the client's LocalIndex changes.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if connects.Load() >= 2 && conn.LocalIndex() != 0 && conn.LocalIndex() != originalIndex {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	if connects.Load() < 2 {
		t.Fatalf("server OnConnect fired %d time(s), want ≥2 (rekey did not happen)", connects.Load())
	}
	if conn.LocalIndex() == originalIndex {
		t.Error("LocalIndex unchanged after rekey — session was not rotated")
	}

	// Post-rekey: verify the connection still works.
	if err := conn.Send(ctx, &wiresocket.Event{Type: 2}); err != nil {
		t.Fatalf("post-rekey Send: %v", err)
	}
	e, err = conn.Recv(ctx)
	if err != nil {
		t.Fatalf("post-rekey Recv: %v", err)
	}
	if e.Type != 12 {
		t.Errorf("post-rekey echo: got type %d, want 12", e.Type)
	}
}

// TestRekeyNonPersistentConnCloses verifies that a non-persistent connection
// is closed automatically when the session key lifetime expires.
//
// The keepalive loop detects needsRekey() on the ticker cadence (KeepaliveInterval)
// and closes the session.  The test uses short intervals to keep it fast.
func TestRekeyNonPersistentConnCloses(t *testing.T) {
	addr, kp := serverSetup(t, wiresocket.ServerConfig{
		OnConnect: func(conn *wiresocket.Conn) { <-conn.Done() },
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := wiresocket.Dial(ctx, addr, wiresocket.DialConfig{
		ServerPublicKey:   kp.Public,
		RekeyAfterTime:    150 * time.Millisecond,
		KeepaliveInterval: 50 * time.Millisecond, // check often enough to detect rekey promptly
		SessionTimeout:    10 * time.Second,       // do not expire due to idle timeout
	})
	if err != nil {
		t.Fatal(err)
	}

	// Wait for the connection to close automatically at key expiry.
	select {
	case <-conn.Done():
		// Expected: non-persistent conn closed itself at rekey time.
	case <-ctx.Done():
		t.Fatal("timeout: non-persistent conn did not close after RekeyAfterTime")
	}

	// Subsequent operations should return an error.
	_, err = conn.Recv(ctx)
	if err == nil {
		t.Error("Recv after rekey-close: want error, got nil")
	}
}

// TestRekeyDrainsReliableFramesBeforeSwitch verifies that pending reliable
// frames are delivered to the peer before the session is closed for rekeying.
//
// The test sends several events, lets them queue up in the reliable send window,
// then waits for the rekey.  All events must be received by the server —
// rekeyDrain waits for ACKs before closing the old session.
func TestRekeyDrainsReliableFramesBeforeSwitch(t *testing.T) {
	const N = 10
	received := make(chan struct{}, N)

	addr, kp := serverSetup(t, wiresocket.ServerConfig{
		OnConnect: func(conn *wiresocket.Conn) {
			for {
				_, err := conn.Recv(context.Background())
				if err != nil {
					return
				}
				received <- struct{}{}
			}
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := wiresocket.Dial(ctx, addr, wiresocket.DialConfig{
		ServerPublicKey: kp.Public,
		ReconnectMin:    20 * time.Millisecond,
		ReconnectMax:    100 * time.Millisecond,
		RekeyAfterTime:  300 * time.Millisecond,
		SessionTimeout:  10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Send N events before the rekey fires.
	for i := range N {
		if err := conn.Send(ctx, &wiresocket.Event{Type: uint8(i + 1)}); err != nil {
			t.Fatalf("Send[%d]: %v", i, err)
		}
	}

	// Wait to collect all N events — even though a rekey may happen mid-flight,
	// the drain step ensures the server receives everything from the old session.
	got := 0
	deadline := time.After(8 * time.Second)
	for got < N {
		select {
		case <-received:
			got++
		case <-deadline:
			t.Fatalf("only received %d/%d events after rekey drain", got, N)
		}
	}
}

// TestRekeyMultipleRotations verifies that a persistent connection can rekey
// multiple times in a row without getting stuck or losing connectivity.
func TestRekeyMultipleRotations(t *testing.T) {
	var connects atomic.Int32
	addr, kp := serverSetup(t, wiresocket.ServerConfig{
		OnConnect: func(conn *wiresocket.Conn) {
			connects.Add(1)
			for {
				e, err := conn.Recv(context.Background())
				if err != nil {
					return
				}
				conn.Send(context.Background(), &wiresocket.Event{Type: e.Type})
			}
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	conn, err := wiresocket.Dial(ctx, addr, wiresocket.DialConfig{
		ServerPublicKey: kp.Public,
		ReconnectMin:    20 * time.Millisecond,
		ReconnectMax:    100 * time.Millisecond,
		RekeyAfterTime:  200 * time.Millisecond,
		SessionTimeout:  10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Wait for at least 3 rekeys (4 total connects).
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if connects.Load() >= 4 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if n := connects.Load(); n < 4 {
		t.Fatalf("only %d server sessions after waiting for 3 rekeys", n)
	}

	// Verify connectivity after multiple rekeys.
	if err := conn.Send(ctx, &wiresocket.Event{Type: 42}); err != nil {
		t.Fatalf("Send after multiple rekeys: %v", err)
	}
	e, err := conn.Recv(ctx)
	if err != nil {
		t.Fatalf("Recv after multiple rekeys: %v", err)
	}
	if e.Type != 42 {
		t.Errorf("echo after rekeys: got type %d, want 42", e.Type)
	}
}

// TestRekeyMultipleChannels verifies that all logical channels continue to
// work correctly after a rekey — reliable state is reset on each channel and
// new sequence numbering begins on the new session.
func TestRekeyMultipleChannels(t *testing.T) {
	const numChannels = 3
	// received[ch] counts events received by the server on that channel.
	var received [numChannels]atomic.Int32

	addr, kp := serverSetup(t, wiresocket.ServerConfig{
		OnConnect: func(conn *wiresocket.Conn) {
			var wg sync.WaitGroup
			for i := range numChannels {
				wg.Add(1)
				go func(id uint16) {
					defer wg.Done()
					ch := conn.Channel(id)
					for {
						e, err := ch.Recv(context.Background())
						if err != nil {
							return
						}
						received[id].Add(1)
						ch.Send(context.Background(), &wiresocket.Event{Type: e.Type})
					}
				}(uint16(i))
			}
			wg.Wait()
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := wiresocket.Dial(ctx, addr, wiresocket.DialConfig{
		ServerPublicKey: kp.Public,
		ReconnectMin:    20 * time.Millisecond,
		ReconnectMax:    100 * time.Millisecond,
		RekeyAfterTime:  200 * time.Millisecond,
		SessionTimeout:  10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	sendAndRecv := func(phase string) {
		t.Helper()
		for i := range numChannels {
			ch := conn.Channel(uint16(i))
			want := uint8(i + 1)
			if err := ch.Send(ctx, &wiresocket.Event{Type: want}); err != nil {
				t.Errorf("%s: ch%d Send: %v", phase, i, err)
				continue
			}
			e, err := ch.Recv(ctx)
			if err != nil {
				t.Errorf("%s: ch%d Recv: %v", phase, i, err)
				continue
			}
			if e.Type != want {
				t.Errorf("%s: ch%d echo got type %d, want %d", phase, i, e.Type, want)
			}
		}
	}

	sendAndRecv("pre-rekey")

	originalIndex := conn.LocalIndex()

	// Wait for the rekey to complete.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if conn.LocalIndex() != 0 && conn.LocalIndex() != originalIndex {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if conn.LocalIndex() == originalIndex {
		t.Fatal("rekey did not happen within timeout")
	}

	sendAndRecv("post-rekey")
}

// TestRekeyCloseWhileReconnecting verifies that calling conn.Close() during
// the reconnect window following a proactive rekey exits cleanly — the
// reconnect loop should see the context cancellation and stop without
// completing a new session.
func TestRekeyCloseWhileReconnecting(t *testing.T) {
	addr, kp := serverSetup(t, wiresocket.ServerConfig{
		OnConnect: func(conn *wiresocket.Conn) { <-conn.Done() },
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Use a long ReconnectMin so the reconnect loop is still sleeping when
	// we call Close(), letting us test cancellation during the backoff wait.
	conn, err := wiresocket.Dial(ctx, addr, wiresocket.DialConfig{
		ServerPublicKey: kp.Public,
		ReconnectMin:    500 * time.Millisecond,
		ReconnectMax:    2 * time.Second,
		RekeyAfterTime:  100 * time.Millisecond,
		SessionTimeout:  10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Wait until the rekey fires and the conn enters the reconnect backoff
	// (LocalIndex == 0 means disconnected).
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if conn.LocalIndex() == 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if conn.LocalIndex() != 0 {
		t.Log("conn reconnected before Close(); test still valid — closing active conn")
	}

	// Close during the reconnect gap (or immediately after reconnect).
	conn.Close()

	select {
	case <-conn.Done():
		// Expected: Close() stopped the reconnect loop promptly.
	case <-ctx.Done():
		t.Fatal("timeout: conn.Done() not closed after conn.Close() during rekey reconnect")
	}
}
