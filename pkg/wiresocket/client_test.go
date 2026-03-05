package wiresocket_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"example.com/pulse/pulse/pkg/wiresocket"
)

// TestHandshakeAndEcho starts a server, dials it, sends a ping, and expects a pong.
func TestHandshakeAndEcho(t *testing.T) {
	addr, kp := serverSetup(t, wiresocket.ServerConfig{
		OnConnect: func(conn *wiresocket.Conn) {
			for {
				e, err := conn.Recv(context.Background())
				if err != nil {
					return
				}
				conn.Send(context.Background(), &wiresocket.Event{
					Type:    2, // pong
					Payload: e.Payload,
				})
			}
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn := mustDial(t, ctx, addr, kp)

	want := []byte("hello, wiresocket!")
	if err := conn.Send(ctx, &wiresocket.Event{Type: 1, Payload: want}); err != nil {
		t.Fatal(err)
	}

	e, err := conn.Recv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if e.Type != 2 {
		t.Errorf("got type %d, want %d", e.Type, 2)
	}
	if string(e.Payload) != string(want) {
		t.Errorf("got payload %q, want %q", e.Payload, want)
	}
}

// TestConcurrentClients dials N clients simultaneously and verifies each receives its echo.
func TestConcurrentClients(t *testing.T) {
	const N = 50

	addr, kp := serverSetup(t, wiresocket.ServerConfig{
		OnConnect: func(conn *wiresocket.Conn) {
			for {
				e, err := conn.Recv(context.Background())
				if err != nil {
					return
				}
				conn.Send(context.Background(), &wiresocket.Event{
					Type:    2, // pong
					Payload: e.Payload,
				})
			}
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	errCh := make(chan error, N)

	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			conn, err := wiresocket.Dial(ctx, addr, wiresocket.DialConfig{
				ServerPublicKey: kp.Public,
			})
			if err != nil {
				errCh <- fmt.Errorf("client %d dial: %w", id, err)
				return
			}
			defer conn.Close()

			msg := fmt.Sprintf("client-%d", id)
			conn.Send(ctx, &wiresocket.Event{Type: 1, Payload: []byte(msg)})
			e, err := conn.Recv(ctx)
			if err != nil {
				errCh <- fmt.Errorf("client %d recv: %w", id, err)
				return
			}
			if string(e.Payload) != msg {
				errCh <- fmt.Errorf("client %d: got %q, want %q", id, e.Payload, msg)
			}
		}(i)
	}

	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}
}

// TestPersistentReconnect verifies that a persistent Conn (ReconnectMin > 0)
// automatically reconnects after the server closes the session.  The client
// must be able to send and receive events both before and after the disconnect.
func TestPersistentReconnect(t *testing.T) {
	// connectedC receives a signal each time OnConnect fires (one per session).
	connectedC := make(chan struct{}, 4)

	addr, kp := serverSetup(t, wiresocket.ServerConfig{
		OnConnect: func(conn *wiresocket.Conn) {
			connectedC <- struct{}{}
			// Echo one event, then close the connection.  Close() sends a
			// typeDisconnect packet so the client's read loop detects the
			// disconnect and triggers a reconnect.
			e, err := conn.Recv(context.Background())
			if err != nil {
				return
			}
			conn.Send(context.Background(), &wiresocket.Event{Type: e.Type + 10})
			conn.Close()
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	conn, err := wiresocket.Dial(ctx, addr, wiresocket.DialConfig{
		ServerPublicKey: kp.Public,
		ReconnectMin:    50 * time.Millisecond,
		ReconnectMax:    200 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// First session: send + receive echo.
	if err := conn.Send(ctx, &wiresocket.Event{Type: 1}); err != nil {
		t.Fatalf("first Send: %v", err)
	}
	e, err := conn.Recv(ctx)
	if err != nil {
		t.Fatalf("first Recv: %v", err)
	}
	if e.Type != 11 {
		t.Errorf("first echo: got type %d, want 11", e.Type)
	}

	// Wait for the server to start a second OnConnect (reconnect completed).
	select {
	case <-connectedC: // first connect
	case <-ctx.Done():
		t.Fatal("timeout waiting for first OnConnect")
	}
	select {
	case <-connectedC: // second connect (after reconnect)
	case <-ctx.Done():
		t.Fatal("timeout waiting for reconnect OnConnect")
	}

	// Second session: should work transparently.
	if err := conn.Send(ctx, &wiresocket.Event{Type: 2}); err != nil {
		t.Fatalf("second Send: %v", err)
	}
	e, err = conn.Recv(ctx)
	if err != nil {
		t.Fatalf("second Recv: %v", err)
	}
	if e.Type != 12 {
		t.Errorf("second echo: got type %d, want 12", e.Type)
	}
}

// TestContextCancelDial verifies that Dial returns promptly when a
// pre-cancelled context is passed.
func TestContextCancelDial(t *testing.T) {
	// Generate a valid keypair to avoid X25519 low-order-point rejection on
	// the zero public key that DialConfig's zero value would produce.
	kp, err := wiresocket.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	port := freePort(t) // grab a port; no server starts on it

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before dialling

	_, err = wiresocket.Dial(ctx, fmt.Sprintf("127.0.0.1:%d", port), wiresocket.DialConfig{
		ServerPublicKey:  kp.Public,
		MaxRetries:       1,
		HandshakeTimeout: 100 * time.Millisecond,
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Dial with cancelled ctx: got %v, want context.Canceled", err)
	}
}
