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
