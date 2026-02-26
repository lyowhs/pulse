package wiresocket_test

// comprehensive_test.go — integration tests for the wiresocket package.
//
// Covered areas:
//   - Frame encode/decode (reliability fields, empty frame)
//   - Channel multiplexing (events route to correct per-channel buffers)
//   - Channel close propagation (client→server and server→client)
//   - Connection lifetime (Close unblocks Recv; Done channel; send/recv errors after close)
//   - Context cancellation (Recv and Dial)
//   - Authentication (Authenticate callback: accept and reject)
//   - ActiveSessions counter
//   - Large fragmented events (64 KB at standard MTU 1472)
//   - Event coalescing (CoalesceInterval)
//   - Reliable delivery in order (N=300 events)
//   - Reliable flow control (window=4, slow consumer, no deadlock or loss)
//   - Bidirectional reliable delivery with piggybacked ACKs
//   - Flush waits for reliable ACKs before returning
//   - Rate-limited delivery (correctness)
//   - Rate-limited delivery timing (slow test; skipped in -short mode)
//   - Concurrent sends on multiple channels

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"example.com/pulse/pulse/pkg/wiresocket"
)

// ─── test helpers ─────────────────────────────────────────────────────────────

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

// ─── Frame encoding ───────────────────────────────────────────────────────────

// TestFrameReliabilityFields verifies that the reliability fields (Seq, AckSeq,
// AckBitmap, WindowSize) survive a full encode/decode round-trip.
func TestFrameReliabilityFields(t *testing.T) {
	cases := []*wiresocket.Frame{
		// Data frame with Seq only.
		{
			ChannelId: 7,
			Seq:       42,
			Events:    []*wiresocket.Event{{Type: 1, Payload: []byte("hi")}},
		},
		// ACK-only frame.
		{
			ChannelId:  0,
			AckSeq:     100,
			AckBitmap:  0xDEADBEEFCAFEBABE,
			WindowSize: 256,
		},
		// Full bidirectional frame.
		{
			ChannelId:  3,
			Seq:        1,
			AckSeq:     5,
			AckBitmap:  0b10101010,
			WindowSize: 128,
			Events: []*wiresocket.Event{
				{Type: 9},
				{Type: 10, Payload: []byte("payload")},
			},
		},
		// All optional fields zero — must round-trip as zero.
		{ChannelId: 255, Events: []*wiresocket.Event{{Type: 1}}},
	}

	for i, f := range cases {
		b := f.Marshal()
		got, err := wiresocket.UnmarshalFrame(b)
		if err != nil {
			t.Fatalf("case %d: UnmarshalFrame: %v", i, err)
		}
		if got.ChannelId != f.ChannelId {
			t.Errorf("case %d: ChannelId: got %d, want %d", i, got.ChannelId, f.ChannelId)
		}
		if got.Seq != f.Seq {
			t.Errorf("case %d: Seq: got %d, want %d", i, got.Seq, f.Seq)
		}
		if got.AckSeq != f.AckSeq {
			t.Errorf("case %d: AckSeq: got %d, want %d", i, got.AckSeq, f.AckSeq)
		}
		if got.AckBitmap != f.AckBitmap {
			t.Errorf("case %d: AckBitmap: got %016x, want %016x", i, got.AckBitmap, f.AckBitmap)
		}
		if got.WindowSize != f.WindowSize {
			t.Errorf("case %d: WindowSize: got %d, want %d", i, got.WindowSize, f.WindowSize)
		}
		if len(got.Events) != len(f.Events) {
			t.Fatalf("case %d: len(Events): got %d, want %d", i, len(got.Events), len(f.Events))
		}
		for j, e := range got.Events {
			orig := f.Events[j]
			if e.Type != orig.Type || string(e.Payload) != string(orig.Payload) {
				t.Errorf("case %d event %d: got {%d %q}, want {%d %q}",
					i, j, e.Type, e.Payload, orig.Type, orig.Payload)
			}
		}
	}
}

// TestFrameEmptyDecode verifies that an empty byte slice decodes without error.
func TestFrameEmptyDecode(t *testing.T) {
	got, err := wiresocket.UnmarshalFrame([]byte{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Events) != 0 {
		t.Errorf("expected 0 events, got %d", len(got.Events))
	}
}

// ─── Channel multiplexing ─────────────────────────────────────────────────────

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

// ─── Connection lifetime ──────────────────────────────────────────────────────

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

// ─── Context cancellation ─────────────────────────────────────────────────────

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

// ─── Authentication ───────────────────────────────────────────────────────────

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

// ─── Session counting ─────────────────────────────────────────────────────────

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

// ─── Large fragmented events ──────────────────────────────────────────────────

// TestLargeFragmentedEvent sends a 64 KiB event at standard MTU (1472 bytes),
// forcing the fragmentation and reassembly path, and verifies the payload
// arrives intact.
func TestLargeFragmentedEvent(t *testing.T) {
	const payloadSize = 64 << 10 // 64 KiB
	const mtu = 1472

	received := make(chan []byte, 1)

	addr, kp := serverSetup(t, wiresocket.ServerConfig{
		MaxPacketSize:       mtu,
		MaxIncompleteFrames: 256,
		WorkChannelSize:     8192,
		OnConnect: func(conn *wiresocket.Conn) {
			e, err := conn.Recv(context.Background())
			if err != nil {
				return
			}
			received <- e.Payload
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn := mustDial(t, ctx, addr, kp, wiresocket.DialConfig{
		MaxPacketSize:       mtu,
		MaxIncompleteFrames: 256,
	})

	payload := make([]byte, payloadSize)
	for i := range payload {
		payload[i] = byte(i & 0xFF)
	}
	if err := conn.Send(ctx, &wiresocket.Event{Type: 7, Payload: payload}); err != nil {
		t.Fatal(err)
	}

	select {
	case got := <-received:
		if len(got) != payloadSize {
			t.Fatalf("payload length: got %d, want %d", len(got), payloadSize)
		}
		for i, b := range got {
			if b != byte(i&0xFF) {
				t.Errorf("payload[%d]: got %d, want %d", i, b, byte(i&0xFF))
				break
			}
		}
	case <-ctx.Done():
		t.Error("timeout: did not receive fragmented event")
	}
}

// ─── Coalescing ───────────────────────────────────────────────────────────────

// TestCoalescedDelivery verifies that all events sent via a coalescing Conn
// are received correctly by the server.
func TestCoalescedDelivery(t *testing.T) {
	const N = 50

	var mu sync.Mutex
	received := make([]uint8, 0, N)
	allDone := make(chan struct{})

	addr, kp := serverSetup(t, wiresocket.ServerConfig{
		OnConnect: func(conn *wiresocket.Conn) {
			for {
				e, err := conn.Recv(context.Background())
				if err != nil {
					return
				}
				mu.Lock()
				received = append(received, e.Type)
				if len(received) == N {
					close(allDone)
				}
				mu.Unlock()
			}
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn := mustDial(t, ctx, addr, kp, wiresocket.DialConfig{
		CoalesceInterval: 500 * time.Microsecond,
	})

	for i := 0; i < N; i++ {
		if err := conn.Send(ctx, &wiresocket.Event{Type: uint8(i + 1)}); err != nil {
			t.Fatal(err)
		}
	}
	conn.Flush(ctx)

	select {
	case <-allDone:
	case <-ctx.Done():
		mu.Lock()
		t.Errorf("timeout: received %d/%d events", len(received), N)
		mu.Unlock()
	}
}

// ─── Reliable delivery ────────────────────────────────────────────────────────

// TestReliableDeliveryInOrder sends N events on a reliable channel and verifies
// that all N arrive at the server in strict sequential order.
func TestReliableDeliveryInOrder(t *testing.T) {
	const N = 300

	receivedC := make(chan uint8, N)

	addr, kp := serverSetup(t, wiresocket.ServerConfig{
		OnConnect: func(conn *wiresocket.Conn) {
			ch := conn.Channel(1)
			for {
				e, err := ch.Recv(context.Background())
				if err != nil {
					return
				}
				receivedC <- e.Type
			}
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn := mustDial(t, ctx, addr, kp)
	ch := conn.Channel(1)
	ch.SetReliable(wiresocket.ReliableCfg{
		WindowSize: 32,
		ACKDelay:   5 * time.Millisecond,
	})

	for i := 0; i < N; i++ {
		if err := ch.Send(ctx, &wiresocket.Event{Type: uint8(i % 251)}); err != nil {
			t.Fatalf("Send[%d]: %v", i, err)
		}
	}
	conn.Flush(ctx)

	for i := 0; i < N; i++ {
		select {
		case got := <-receivedC:
			want := uint8(i % 251)
			if got != want {
				t.Errorf("event[%d]: got type %d, want %d (out-of-order?)", i, got, want)
			}
		case <-ctx.Done():
			t.Fatalf("timeout: received %d/%d events", i, N)
		}
	}

	// On a clean loopback connection there should be no retransmits.
	if r := ch.Retransmits(); r != 0 {
		t.Logf("note: %d retransmit(s) observed on loopback", r)
	}
}

// TestReliableFlowControl sends many events against a slow server consumer
// with a tiny flow-control window, verifying that all events arrive in order
// and the sender does not deadlock.
func TestReliableFlowControl(t *testing.T) {
	const N = 200
	const window = 4

	receivedC := make(chan uint8, N)

	addr, kp := serverSetup(t, wiresocket.ServerConfig{
		OnConnect: func(conn *wiresocket.Conn) {
			ch := conn.Channel(1)
			for {
				e, err := ch.Recv(context.Background())
				if err != nil {
					return
				}
				receivedC <- e.Type
				time.Sleep(2 * time.Millisecond) // slow consumer
			}
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn := mustDial(t, ctx, addr, kp)
	ch := conn.Channel(1)
	ch.SetReliable(wiresocket.ReliableCfg{
		WindowSize: window,
		ACKDelay:   5 * time.Millisecond,
	})

	for i := 0; i < N; i++ {
		if err := ch.Send(ctx, &wiresocket.Event{Type: uint8(i % 251)}); err != nil {
			t.Fatalf("Send[%d]: %v", i, err)
		}
	}
	conn.Flush(ctx)

	for i := 0; i < N; i++ {
		select {
		case got := <-receivedC:
			want := uint8(i % 251)
			if got != want {
				t.Errorf("event[%d]: type=%d, want %d (out-of-order?)", i, got, want)
			}
		case <-ctx.Done():
			t.Fatalf("timeout: only received %d/%d events", i, N)
		}
	}
}

// TestReliableBidirectional verifies two-way reliable delivery on the same
// channel with piggybacked ACKs: both sides send and receive N events in order.
func TestReliableBidirectional(t *testing.T) {
	const N = 100

	srvReceivedC := make(chan uint8, N)
	cliReceivedC := make(chan uint8, N)
	// srvReady is closed by the server after SetReliable so the client does not
	// start sending until the server's reliable state is fully initialised.
	// Without this synchronisation the server's auto-created state (which has a
	// default config) could be mid-flight when SetReliable replaces it, leaving
	// the new state with a stale expectSeq and causing frames to be lost.
	srvReady := make(chan struct{})

	// WorkerCount: 1 prevents concurrent workers from delivering packets to
	// onRecv out-of-order, which would overflow the 64-slot OOO window and
	// permanently drop frames when the default send window (256) is in use.
	addr, kp := serverSetup(t, wiresocket.ServerConfig{
		WorkerCount: 1,
		OnConnect: func(conn *wiresocket.Conn) {
			ch := conn.Channel(1)
			ch.SetReliable(wiresocket.ReliableCfg{ACKDelay: 5 * time.Millisecond})
			close(srvReady)
			// Use WaitGroup to keep OnConnect alive until both goroutines
			// finish.  The server's wrapper goroutine calls sess.close() in
			// a deferred function when OnConnect returns, so returning early
			// (before the goroutines complete) would tear down the session
			// before any frames are exchanged.
			var wg sync.WaitGroup
			wg.Add(1)
			go func() { // server receive loop
				defer wg.Done()
				for {
					e, err := ch.Recv(context.Background())
					if err != nil {
						return
					}
					srvReceivedC <- e.Type
				}
			}()
			wg.Add(1)
			go func() { // server send loop
				defer wg.Done()
				for i := 0; i < N; i++ {
					if err := ch.Send(context.Background(), &wiresocket.Event{
						Type: uint8(200 - i%200),
					}); err != nil {
						return
					}
				}
			}()
			wg.Wait()
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn := mustDial(t, ctx, addr, kp)
	ch := conn.Channel(1)
	ch.SetReliable(wiresocket.ReliableCfg{ACKDelay: 5 * time.Millisecond})

	// Wait for the server to finish calling SetReliable before sending any
	// reliable frames, so the server's expectSeq is initialised correctly.
	select {
	case <-srvReady:
	case <-ctx.Done():
		t.Fatal("timeout waiting for server to be ready")
	}

	// Client send loop.
	go func() {
		for i := 0; i < N; i++ {
			ch.Send(ctx, &wiresocket.Event{Type: uint8(i % 251)})
		}
	}()

	// Client receive loop.
	go func() {
		for {
			e, err := ch.Recv(ctx)
			if err != nil {
				return
			}
			cliReceivedC <- e.Type
		}
	}()

	// Verify N events from server arrive at client in order.
	for i := 0; i < N; i++ {
		select {
		case got := <-cliReceivedC:
			want := uint8(200 - i%200)
			if got != want {
				t.Errorf("cli[%d]: got %d, want %d", i, got, want)
			}
		case <-ctx.Done():
			t.Fatalf("timeout: client received %d/%d events from server", i, N)
		}
	}

	// Verify N events from client arrive at server in order.
	for i := 0; i < N; i++ {
		select {
		case got := <-srvReceivedC:
			want := uint8(i % 251)
			if got != want {
				t.Errorf("srv[%d]: got %d, want %d", i, got, want)
			}
		case <-ctx.Done():
			t.Fatalf("timeout: server received %d/%d events from client", i, N)
		}
	}
}

// TestReliableFlushDrainsWindow verifies that Flush returns only after all
// outstanding reliable frames have been ACKed, leaving the window available
// for subsequent sends.
func TestReliableFlushDrainsWindow(t *testing.T) {
	const N = 50

	addr, kp := serverSetup(t, wiresocket.ServerConfig{
		OnConnect: func(conn *wiresocket.Conn) {
			ch := conn.Channel(1)
			for {
				if _, err := ch.Recv(context.Background()); err != nil {
					return
				}
			}
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn := mustDial(t, ctx, addr, kp)
	ch := conn.Channel(1)
	ch.SetReliable(wiresocket.ReliableCfg{
		WindowSize: 8,
		ACKDelay:   5 * time.Millisecond,
	})

	for i := 0; i < N; i++ {
		if err := ch.Send(ctx, &wiresocket.Event{Type: 1}); err != nil {
			t.Fatalf("Send[%d]: %v", i, err)
		}
	}

	// Flush must not return until all N sends are ACKed.
	conn.Flush(ctx)

	// After Flush, the window should be entirely free. A subsequent send must
	// complete immediately (not block on window exhaustion).
	sendCtx, sc := context.WithTimeout(ctx, 500*time.Millisecond)
	defer sc()
	if err := ch.Send(sendCtx, &wiresocket.Event{Type: 2}); err != nil {
		t.Errorf("Send after Flush: %v (window should be clear)", err)
	}
}

// TestRetransmitCounterHappyPath verifies that Retransmits() returns 0 after a
// clean reliable delivery on loopback (no packets lost).
func TestRetransmitCounterHappyPath(t *testing.T) {
	const N = 100

	// WorkerCount: 1 prevents concurrent workers from processing packets
	// out-of-order, which would overflow the 64-slot OOO window and drop frames.
	var srvReceived atomic.Int64
	addr, kp := serverSetup(t, wiresocket.ServerConfig{
		WorkerCount: 1,
		OnConnect: func(conn *wiresocket.Conn) {
			ch := conn.Channel(1)
			for {
				if _, err := ch.Recv(context.Background()); err != nil {
					return
				}
				srvReceived.Add(1)
			}
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn := mustDial(t, ctx, addr, kp)
	ch := conn.Channel(1)
	// Use a large BaseRTO so the retransmit timer never fires before the
	// server's ACK arrives (~20 ms on loopback).  The default 200 ms RTO
	// can race with the server's auto-created ACKDelay=20 ms under load,
	// producing spurious retransmits that make this assertion flaky.
	ch.SetReliable(wiresocket.ReliableCfg{BaseRTO: 5 * time.Second})

	for i := 0; i < N; i++ {
		if err := ch.Send(ctx, &wiresocket.Event{Type: 1}); err != nil {
			t.Fatalf("Send[%d]: %v", i, err)
		}
	}
	conn.Flush(ctx)

	r := ch.Retransmits()
	got := srvReceived.Load()
	if r != 0 {
		t.Errorf("Retransmits() = %d on clean loopback, want 0 (server received %d/%d events)", r, got, N)
	}
}

// ─── Rate limiting ────────────────────────────────────────────────────────────

// TestRateLimitDelivery verifies that a rate-limited connection still delivers
// all data correctly (correctness, not timing).
func TestRateLimitDelivery(t *testing.T) {
	const N = 20
	const bps int64 = 10 << 20 // 10 MB/s — high enough that test stays fast

	var received atomic.Int64

	addr, kp := serverSetup(t, wiresocket.ServerConfig{
		SendRateLimitBPS: bps,
		OnConnect: func(conn *wiresocket.Conn) {
			for {
				e, err := conn.Recv(context.Background())
				if err != nil {
					return
				}
				received.Add(1)
				conn.Send(context.Background(), e) // echo
			}
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn := mustDial(t, ctx, addr, kp, wiresocket.DialConfig{
		SendRateLimitBPS: bps,
	})

	payload := make([]byte, 1024)
	for i := 0; i < N; i++ {
		if err := conn.Send(ctx, &wiresocket.Event{Type: 1, Payload: payload}); err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Recv(ctx); err != nil {
			t.Fatal(err)
		}
	}

	if got := received.Load(); got != int64(N) {
		t.Errorf("server received %d events, want %d", got, N)
	}
}

// TestRateLimitTiming verifies that a tight rate limit actually slows down
// sends.  This test is skipped in -short mode because it deliberately takes
// over a second.
func TestRateLimitTiming(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping timing-sensitive test in -short mode")
	}

	// 50 KB/s with burst = 100 KB.
	// Send 40 events × 5 KB = 200 KB total.
	// First 100 KB (20 events) drain the burst instantly.
	// Remaining 100 KB takes ≥ 2 s at 50 KB/s.
	const bps int64 = 50_000
	const payloadSize = 5_000
	const N = 40

	addr, kp := serverSetup(t, wiresocket.ServerConfig{
		OnConnect: func(conn *wiresocket.Conn) { <-conn.Done() },
	})

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn := mustDial(t, ctx, addr, kp, wiresocket.DialConfig{
		SendRateLimitBPS: bps,
	})

	payload := make([]byte, payloadSize)
	start := time.Now()
	for i := 0; i < N; i++ {
		if err := conn.Send(ctx, &wiresocket.Event{Type: 1, Payload: payload}); err != nil {
			t.Fatal(err)
		}
	}
	elapsed := time.Since(start)

	// After the 100 KB burst, the remaining 100 KB must take ≥ 1.5 s.
	const wantMin = 1500 * time.Millisecond
	if elapsed < wantMin {
		t.Errorf("elapsed %v < %v: rate limiting does not appear to be working", elapsed, wantMin)
	}
}

// ─── Concurrency ──────────────────────────────────────────────────────────────

// TestConcurrentChannelSends spawns G goroutines each sending P events on a
// distinct channel, and verifies that all G×P events arrive at the server.
func TestConcurrentChannelSends(t *testing.T) {
	const G = 8   // goroutines / channels
	const P = 25  // events per goroutine

	var received atomic.Int64

	addr, kp := serverSetup(t, wiresocket.ServerConfig{
		OnConnect: func(conn *wiresocket.Conn) {
			var wg sync.WaitGroup
			for id := uint8(1); id <= G; id++ {
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
	for id := uint8(1); id <= G; id++ {
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

	addr, kp := serverSetup(t, wiresocket.ServerConfig{
		OnConnect: func(conn *wiresocket.Conn) {
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
	conn := mustDial(t, ctx, addr, kp)

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
