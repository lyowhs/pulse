package wiresocket_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"example.com/pulse/pulse/pkg/wiresocket"
)

// TestChannelMultiplexing verifies that events sent on different channels are
// routed to the correct per-channel receive buffers and not cross-delivered.
func TestChannelMultiplexing(t *testing.T) {
	// Server: echo ch1 events with type+1, ch2 events with type+2.
	addr, kp := serverSetup(t, wiresocket.ServerConfig{
		OnConnect: func(conn *wiresocket.Conn) {
			ch1 := conn.Channel(1)
			ch2 := conn.Channel(2)
			var wg sync.WaitGroup
			wg.Add(2)
			go func() {
				defer wg.Done()
				for {
					e, err := ch1.Recv(context.Background())
					if err != nil {
						return
					}
					ch1.Send(context.Background(), &wiresocket.Event{
						Type:    e.Type + 1,
						Payload: e.Payload,
					})
				}
			}()
			go func() {
				defer wg.Done()
				for {
					e, err := ch2.Recv(context.Background())
					if err != nil {
						return
					}
					ch2.Send(context.Background(), &wiresocket.Event{
						Type:    e.Type + 2,
						Payload: e.Payload,
					})
				}
			}()
			wg.Wait()
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn := mustDial(t, ctx, addr, kp)

	ch1 := conn.Channel(1)
	ch2 := conn.Channel(2)

	ch1.Send(ctx, &wiresocket.Event{Type: 10, Payload: []byte("from-ch1")})
	ch2.Send(ctx, &wiresocket.Event{Type: 20, Payload: []byte("from-ch2")})

	e1, err := ch1.Recv(ctx)
	if err != nil {
		t.Fatal("ch1.Recv:", err)
	}
	if e1.Type != 11 || string(e1.Payload) != "from-ch1" {
		t.Errorf("ch1: got {%d %q}, want {11 from-ch1}", e1.Type, e1.Payload)
	}

	e2, err := ch2.Recv(ctx)
	if err != nil {
		t.Fatal("ch2.Recv:", err)
	}
	if e2.Type != 22 || string(e2.Payload) != "from-ch2" {
		t.Errorf("ch2: got {%d %q}, want {22 from-ch2}", e2.Type, e2.Payload)
	}
}

// TestChannelCloseFromClient verifies that closing a channel on the client side
// causes the server-side Recv on that channel to return an error.
func TestChannelCloseFromClient(t *testing.T) {
	chErrC := make(chan error, 1)

	addr, kp := serverSetup(t, wiresocket.ServerConfig{
		OnConnect: func(conn *wiresocket.Conn) {
			ch := conn.Channel(1)
			// Send a ready signal so the client knows the server goroutine is running.
			conn.Send(context.Background(), &wiresocket.Event{Type: 99})
			// Now wait — should unblock when client closes ch1.
			_, err := ch.Recv(context.Background())
			chErrC <- err
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn := mustDial(t, ctx, addr, kp)

	// Wait for server's ready signal before closing.
	if _, err := conn.Recv(ctx); err != nil {
		t.Fatal("waiting for server ready:", err)
	}

	conn.Channel(1).Close()

	select {
	case err := <-chErrC:
		if err == nil {
			t.Error("server ch1.Recv: want error after client channel close, got nil")
		}
	case <-ctx.Done():
		t.Error("timeout: server ch1.Recv did not return after client closed ch1")
	}
}

// TestChannelCloseFromServer verifies that closing a channel from the server
// causes the client-side Recv on that channel to return ErrChannelClosed.
func TestChannelCloseFromServer(t *testing.T) {
	srvClosedC := make(chan struct{})

	addr, kp := serverSetup(t, wiresocket.ServerConfig{
		OnConnect: func(conn *wiresocket.Conn) {
			ch := conn.Channel(1)
			// Wait for the client's trigger event.
			ch.Recv(context.Background())
			// Close the channel from the server side.
			ch.Close()
			close(srvClosedC)
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn := mustDial(t, ctx, addr, kp)
	ch := conn.Channel(1)

	// Send the trigger event.
	ch.Send(ctx, &wiresocket.Event{Type: 1})

	select {
	case <-srvClosedC:
	case <-ctx.Done():
		t.Fatal("timeout: server did not close ch1")
	}

	// Allow the close notification to travel from server to client.
	time.Sleep(50 * time.Millisecond)

	_, err := ch.Recv(ctx)
	if !errors.Is(err, wiresocket.ErrChannelClosed) {
		t.Errorf("client ch.Recv after server close: got %v, want ErrChannelClosed", err)
	}
}

// TestSendAfterChannelClose verifies that ch.Send returns ErrChannelClosed
// after the channel has been closed locally.
func TestSendAfterChannelClose(t *testing.T) {
	addr, kp := serverSetup(t, wiresocket.ServerConfig{
		OnConnect: func(conn *wiresocket.Conn) { <-conn.Done() },
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn := mustDial(t, ctx, addr, kp)

	ch := conn.Channel(1)
	ch.Close()

	err := ch.Send(ctx, &wiresocket.Event{Type: 1})
	if !errors.Is(err, wiresocket.ErrChannelClosed) {
		t.Errorf("Send after channel Close: got %v, want ErrChannelClosed", err)
	}
}

// TestRecvAfterChannelClose verifies that ch.Recv returns ErrChannelClosed
// after the channel has been closed locally.
func TestRecvAfterChannelClose(t *testing.T) {
	addr, kp := serverSetup(t, wiresocket.ServerConfig{
		OnConnect: func(conn *wiresocket.Conn) { <-conn.Done() },
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn := mustDial(t, ctx, addr, kp)

	ch := conn.Channel(1)
	ch.Close()

	_, err := ch.Recv(ctx)
	if !errors.Is(err, wiresocket.ErrChannelClosed) {
		t.Errorf("Recv after channel Close: got %v, want ErrChannelClosed", err)
	}
}

// TestConcurrentChannelSends spawns G goroutines each sending P events on a
// distinct channel, and verifies that all G×P events arrive at the server.
func TestConcurrentChannelSends(t *testing.T) {
	const G = 8  // goroutines / channels
	const P = 25 // events per goroutine

	var received atomic.Int64

	addr, kp := serverSetup(t, wiresocket.ServerConfig{
		OnConnect: func(conn *wiresocket.Conn) {
			var wg sync.WaitGroup
			for id := uint16(1); id <= G; id++ {
				ch := conn.Channel(id)
				wg.Add(1)
				go func(ch *wiresocket.Channel) {
					defer wg.Done()
					for {
						if _, err := ch.Recv(context.Background()); err != nil {
							return
						}
						received.Add(1)
					}
				}(ch)
			}
			wg.Wait()
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn := mustDial(t, ctx, addr, kp)

	var wg sync.WaitGroup
	for id := uint16(1); id <= G; id++ {
		ch := conn.Channel(id)
		wg.Add(1)
		go func(ch *wiresocket.Channel) {
			defer wg.Done()
			for i := 0; i < P; i++ {
				ch.Send(ctx, &wiresocket.Event{Type: uint8(i)})
			}
		}(ch)
	}
	wg.Wait()

	// Wait for all events to arrive.
	const want = int64(G * P)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && received.Load() < want {
		time.Sleep(10 * time.Millisecond)
	}
	if got := received.Load(); got != want {
		t.Errorf("concurrent sends: server received %d events, want %d", got, want)
	}
}

// TestConcurrentSendRecv verifies that a single connection handles concurrent
// senders and receivers without data corruption or deadlock.
func TestConcurrentSendRecv(t *testing.T) {
	const workers = 4
	const perWorker = 50

	// Disable reliable delivery: this test exercises concurrent-send safety,
	// not in-order delivery.  With 4 concurrent senders the OOO sequence-number
	// gaps can exceed the 64-slot SACK buffer, causing frame drops and
	// retransmit timeouts that exceed the test deadline.
	addr, kp := serverSetup(t, wiresocket.ServerConfig{
		OnConnect: func(conn *wiresocket.Conn) {
			conn.Channel(0).SetUnreliable()
			for {
				e, err := conn.Recv(context.Background())
				if err != nil {
					return
				}
				conn.Send(context.Background(), e)
			}
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn := mustDial(t, ctx, addr, kp, wiresocket.DialConfig{})
	conn.Channel(0).SetUnreliable()

	var (
		sendWG sync.WaitGroup
		recvWG sync.WaitGroup
		total  atomic.Int64
	)

	// One receiver goroutine.
	recvWG.Add(1)
	go func() {
		defer recvWG.Done()
		for {
			select {
			case <-conn.Done():
				return
			case <-ctx.Done():
				return
			case <-conn.Events():
				total.Add(1)
			}
		}
	}()

	// Multiple sender goroutines.
	for i := 0; i < workers; i++ {
		sendWG.Add(1)
		go func() {
			defer sendWG.Done()
			for j := 0; j < perWorker; j++ {
				conn.Send(ctx, &wiresocket.Event{Type: 1})
			}
		}()
	}
	sendWG.Wait()
	conn.Flush(ctx)

	// Wait for all echoes.
	const want = int64(workers * perWorker)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && total.Load() < want {
		time.Sleep(10 * time.Millisecond)
	}
	if got := total.Load(); got != want {
		t.Errorf("concurrent send/recv: received %d echoes, want %d", got, want)
	}

	conn.Close()
	recvWG.Wait()
}
