package wiresocket_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"example.com/pulse/pulse/pkg/wiresocket"
)

// TestConnCloseCancelsRecv verifies that conn.Close() unblocks a goroutine
// blocked in conn.Recv.
func TestConnCloseCancelsRecv(t *testing.T) {
	addr, kp := serverSetup(t, wiresocket.ServerConfig{
		OnConnect: func(conn *wiresocket.Conn) { <-conn.Done() },
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// Use Dial directly so we control when Close is called.
	conn, err := wiresocket.Dial(ctx, addr, wiresocket.DialConfig{
		ServerPublicKey: kp.Public,
	})
	if err != nil {
		t.Fatal(err)
	}

	errC := make(chan error, 1)
	go func() {
		_, err := conn.Recv(ctx)
		errC <- err
	}()

	time.Sleep(20 * time.Millisecond) // ensure Recv is blocking
	conn.Close()

	select {
	case err := <-errC:
		if !errors.Is(err, wiresocket.ErrConnClosed) {
			t.Errorf("Recv after Close: got %v, want ErrConnClosed", err)
		}
	case <-ctx.Done():
		t.Error("timeout: Recv did not return after conn.Close()")
	}
}

// TestConnDone verifies that conn.Done() is closed after conn.Close().
func TestConnDone(t *testing.T) {
	addr, kp := serverSetup(t, wiresocket.ServerConfig{
		OnConnect: func(conn *wiresocket.Conn) { <-conn.Done() },
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := wiresocket.Dial(ctx, addr, wiresocket.DialConfig{
		ServerPublicKey: kp.Public,
	})
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()

	select {
	case <-conn.Done():
	case <-ctx.Done():
		t.Error("timeout: conn.Done() not closed after conn.Close()")
	}
}

// TestSendAfterClose verifies that conn.Send returns ErrConnClosed after the
// connection has been closed.
func TestSendAfterClose(t *testing.T) {
	addr, kp := serverSetup(t, wiresocket.ServerConfig{
		OnConnect: func(conn *wiresocket.Conn) { <-conn.Done() },
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := wiresocket.Dial(ctx, addr, wiresocket.DialConfig{
		ServerPublicKey: kp.Public,
	})
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()

	err = conn.Send(ctx, &wiresocket.Event{Type: 1})
	if !errors.Is(err, wiresocket.ErrConnClosed) && !errors.Is(err, wiresocket.ErrChannelClosed) {
		t.Errorf("Send after Close: got %v, want ErrConnClosed or ErrChannelClosed", err)
	}
}

// TestRecvAfterClose verifies that conn.Recv returns ErrConnClosed after the
// connection has been closed.
func TestRecvAfterClose(t *testing.T) {
	addr, kp := serverSetup(t, wiresocket.ServerConfig{
		OnConnect: func(conn *wiresocket.Conn) { <-conn.Done() },
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := wiresocket.Dial(ctx, addr, wiresocket.DialConfig{
		ServerPublicKey: kp.Public,
	})
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()

	_, err = conn.Recv(ctx)
	if !errors.Is(err, wiresocket.ErrConnClosed) {
		t.Errorf("Recv after Close: got %v, want ErrConnClosed", err)
	}
}

// TestRemoteAddr verifies that RemoteAddr returns a non-empty string after a
// successful handshake.
func TestRemoteAddr(t *testing.T) {
	addr, kp := serverSetup(t, wiresocket.ServerConfig{
		OnConnect: func(conn *wiresocket.Conn) { <-conn.Done() },
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn := mustDial(t, ctx, addr, kp)
	got := conn.RemoteAddr()
	if got == "" {
		t.Error("RemoteAddr() returned empty string after successful dial")
	}
}

// TestLocalIndex verifies that LocalIndex returns a non-zero value after a
// successful handshake.
func TestLocalIndex(t *testing.T) {
	addr, kp := serverSetup(t, wiresocket.ServerConfig{
		OnConnect: func(conn *wiresocket.Conn) { <-conn.Done() },
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn := mustDial(t, ctx, addr, kp)
	if idx := conn.LocalIndex(); idx == 0 {
		// LocalIndex() == 0 is astronomically unlikely for a random uint32,
		// and the library guarantees non-zero on a live session.
		t.Error("LocalIndex() == 0, want non-zero after successful handshake")
	}
}

// TestCongestionRateKBpsNoCCReturnsZero verifies that CongestionRateKBps
// returns 0 when no CongestionControl is configured.
func TestCongestionRateKBpsNoCCReturnsZero(t *testing.T) {
	addr, kp := serverSetup(t, wiresocket.ServerConfig{
		OnConnect: func(conn *wiresocket.Conn) { <-conn.Done() },
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn := mustDial(t, ctx, addr, kp)
	if rate := conn.CongestionRateKBps(); rate != 0 {
		t.Errorf("CongestionRateKBps() = %.1f, want 0 (no CC configured)", rate)
	}
}

// TestSendFrame verifies that SendFrame delivers all events in the frame to
// the server.
func TestSendFrame(t *testing.T) {
	const N = 5
	received := make(chan uint8, N)

	addr, kp := serverSetup(t, wiresocket.ServerConfig{
		OnConnect: func(conn *wiresocket.Conn) {
			for {
				e, err := conn.Recv(context.Background())
				if err != nil {
					return
				}
				received <- e.Type
			}
		},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn := mustDial(t, ctx, addr, kp)

	// Build a single frame with N events and send it in one call.
	events := make([]*wiresocket.Event, N)
	for i := range events {
		events[i] = &wiresocket.Event{Type: uint8(i + 1)}
	}
	frame := &wiresocket.Frame{Events: events}
	if err := conn.SendFrame(ctx, frame); err != nil {
		t.Fatalf("SendFrame: %v", err)
	}

	for i := 0; i < N; i++ {
		select {
		case got := <-received:
			if got != uint8(i+1) {
				t.Errorf("event[%d]: got type %d, want %d", i, got, i+1)
			}
		case <-ctx.Done():
			t.Fatalf("timeout: received %d/%d events", i, N)
		}
	}
}

// TestContextCancelRecv verifies that cancelling the context passed to Recv
// causes it to return context.Canceled.
func TestContextCancelRecv(t *testing.T) {
	addr, kp := serverSetup(t, wiresocket.ServerConfig{
		OnConnect: func(conn *wiresocket.Conn) { <-conn.Done() },
	})

	outerCtx, outerCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer outerCancel()
	conn := mustDial(t, outerCtx, addr, kp)

	recvCtx, recvCancel := context.WithCancel(context.Background())
	errC := make(chan error, 1)
	go func() {
		_, err := conn.Recv(recvCtx)
		errC <- err
	}()

	time.Sleep(20 * time.Millisecond) // ensure Recv is blocking
	recvCancel()

	select {
	case err := <-errC:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Recv with cancelled ctx: got %v, want context.Canceled", err)
		}
	case <-outerCtx.Done():
		t.Error("timeout: Recv did not return after context cancel")
	}
}
