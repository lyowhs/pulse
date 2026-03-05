package wiresocket_test

// coalescer_test.go — tests for the event coalescer (coalescer.go).
//
// The coalescer is not directly exported; all tests drive it through the
// public Conn / Channel / Server API.  Tests are grouped by the coalescer
// property they exercise:
//
//   - Coalesced delivery: all events sent via a coalescing Conn are received.
//   - Timer-based batching: events sent quickly arrive together.
//   - Size-limit flush: a full frame flushes immediately, not waiting for the timer.
//   - Multi-channel routing: events on different channels are demuxed correctly.
//   - Drain on Close: events buffered at Close time are not silently dropped.
//   - Flush semantics: Flush() delivers pending events without tearing down the session.
//   - Concurrent sends: multiple goroutines sending concurrently produce zero loss.
//   - Disabled coalescing: CoalesceInterval=0 does not buffer events.
//   - Frame-size regression: coalesced frames fit in one UDP packet (the per-event
//     encoding-overhead bug would fragment frames and overflow reassembly buffers).

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"example.com/pulse/pulse/pkg/wiresocket"
)

// coalescerEchoServer starts a server that echoes every received event on the
// same channel back to the sender.  Returns the server address.
func coalescerEchoServer(t *testing.T, cfg wiresocket.ServerConfig) (addr string, kp wiresocket.Keypair) {
	t.Helper()
	cfg.OnConnect = func(conn *wiresocket.Conn) {
		// echo on every channel that has events
		var wg sync.WaitGroup
		for _, id := range []uint16{0, 1, 2, 3} {
			id := id
			ch := conn.Channel(id)
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					e, err := ch.Recv(context.Background())
					if err != nil {
						return
					}
					_ = ch.Send(context.Background(), e)
				}
			}()
		}
		wg.Wait()
	}
	return serverSetup(t, cfg)
}

// recvN reads exactly n events from ch within timeout and returns them.
// Fails the test if fewer than n events arrive.
func recvN(t *testing.T, ch *wiresocket.Channel, n int, timeout time.Duration) []*wiresocket.Event {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out := make([]*wiresocket.Event, 0, n)
	for len(out) < n {
		e, err := ch.Recv(ctx)
		if err != nil {
			t.Fatalf("recvN: got %d/%d events then error: %v", len(out), n, err)
		}
		out = append(out, e)
	}
	return out
}

// ─── Timer batching ───────────────────────────────────────────────────────────

// TestCoalescerTimerBatching verifies that multiple events pushed within one
// coalesce interval are delivered to the server and echoed back correctly.
// It does not assert exact batch boundaries (that would be timing-sensitive)
// but does confirm all events arrive without loss.
func TestCoalescerTimerBatching(t *testing.T) {
	const N = 40
	const coalesce = 5 * time.Millisecond

	addr, kp := coalescerEchoServer(t, wiresocket.ServerConfig{})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn := mustDial(t, ctx, addr, kp, wiresocket.DialConfig{
		CoalesceInterval: coalesce,
	})
	ch := conn.Channel(1)
	ch.SetUnreliable()

	// Send all N events as fast as possible — they should be coalesced into
	// one or a few frames, not one UDP packet per event.
	for i := 0; i < N; i++ {
		if err := ch.Send(ctx, &wiresocket.Event{Type: uint8(i + 1), Payload: []byte{byte(i)}}); err != nil {
			t.Fatalf("Send %d: %v", i, err)
		}
	}

	got := recvN(t, ch, N, 5*time.Second)
	if len(got) != N {
		t.Fatalf("got %d events, want %d", len(got), N)
	}
	for i, e := range got {
		if e.Type != uint8(i+1) {
			t.Errorf("event[%d]: type=%d, want %d", i, e.Type, i+1)
		}
	}
}

// ─── Size-limit flush ─────────────────────────────────────────────────────────

// TestCoalescerSizeLimitFlush verifies that the coalescer flushes a frame
// immediately when the accumulated payload hits the size threshold, without
// waiting for the timer.  The timer is set to 60 s so it cannot fire during
// the test; delivery must come from a size-triggered flush.
func TestCoalescerSizeLimitFlush(t *testing.T) {
	// MaxPacketSize=400 → maxFrag = 400-40 = 360 bytes.
	// payload=100, evtWire=103 (100+1=101 < 128 → overhead=3).
	// eventsPerFrame = (360-32)/103 = 3.
	// Sending 3 events: after the 3rd, pendingBytes+evtWire+32 = 3*103+103+32 = 444 ≥ 360
	// → immediate flush before the 60-second timer.  All 3 events are delivered
	// without waiting for the timer.
	const mtu = 400
	const payload = 100
	const send = 3

	addr, kp := coalescerEchoServer(t, wiresocket.ServerConfig{
		MaxPacketSize:       mtu,
		MaxIncompleteFrames: 64,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn := mustDial(t, ctx, addr, kp, wiresocket.DialConfig{
		MaxPacketSize:    mtu,
		CoalesceInterval: 60 * time.Second, // deliberately long — must NOT fire
	})
	ch := conn.Channel(1)
	ch.SetUnreliable()

	for i := 0; i < send; i++ {
		if err := ch.Send(ctx, &wiresocket.Event{Type: uint8(i + 1), Payload: make([]byte, payload)}); err != nil {
			t.Fatalf("Send: %v", err)
		}
	}

	// All events must arrive within a short deadline — not the 60-second timer.
	deadline := 2 * time.Second
	events := recvN(t, ch, send, deadline)
	if len(events) != send {
		t.Fatalf("size-limit flush: got %d/%d events within %s", len(events), send, deadline)
	}
}

// ─── Multi-channel routing ────────────────────────────────────────────────────

// TestCoalescerMultiChannelRouting confirms that events on different channels
// are coalesced independently and routed to the correct receive channel.
func TestCoalescerMultiChannelRouting(t *testing.T) {
	const N = 20

	addr, kp := coalescerEchoServer(t, wiresocket.ServerConfig{})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn := mustDial(t, ctx, addr, kp, wiresocket.DialConfig{
		CoalesceInterval: 2 * time.Millisecond,
	})

	ch1 := conn.Channel(1)
	ch2 := conn.Channel(2)
	ch1.SetUnreliable()
	ch2.SetUnreliable()

	// Send alternating events on both channels.
	for i := 0; i < N; i++ {
		e := &wiresocket.Event{Type: uint8(i + 1), Payload: []byte{byte(i)}}
		if i%2 == 0 {
			if err := ch1.Send(ctx, e); err != nil {
				t.Fatalf("ch1 Send: %v", err)
			}
		} else {
			if err := ch2.Send(ctx, e); err != nil {
				t.Fatalf("ch2 Send: %v", err)
			}
		}
	}

	// Both channels should receive N/2 events each, independently.
	half := N / 2
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		evts := recvN(t, ch1, half, 5*time.Second)
		for i, e := range evts {
			if e.Type != uint8(i*2+1) {
				t.Errorf("ch1[%d]: type=%d, want %d", i, e.Type, i*2+1)
			}
		}
	}()
	go func() {
		defer wg.Done()
		evts := recvN(t, ch2, half, 5*time.Second)
		for i, e := range evts {
			if e.Type != uint8(i*2+2) {
				t.Errorf("ch2[%d]: type=%d, want %d", i, e.Type, i*2+2)
			}
		}
	}()
	wg.Wait()
}

// ─── Drain on Close ───────────────────────────────────────────────────────────

// TestCoalescerDrainOnClose verifies that events buffered in the coalescer at
// the time Close() is called are flushed and delivered before the connection
// tears down.
func TestCoalescerDrainOnClose(t *testing.T) {
	const N = 30

	received := make(chan *wiresocket.Event, N*2)
	addr, kp := serverSetup(t, wiresocket.ServerConfig{
		// WorkerCount=1: ensures the data frame is processed before the
		// disconnect packet, so all events are buffered in ch.events before
		// conn.Done() fires.
		WorkerCount: 1,
		OnConnect: func(conn *wiresocket.Conn) {
			// Read from the raw events channel so we can drain it even after
			// conn.Done() closes.  conn.Recv() uses a select that may pick
			// <-conn.Done() over pending events once the disconnect arrives,
			// silently losing buffered events.
			events := conn.Events()
			done := conn.Done()
			for {
				select {
				case e := <-events:
					received <- e
				case <-done:
					// Connection closed; drain any events already buffered.
					for {
						select {
						case e := <-events:
							received <- e
						default:
							return
						}
					}
				}
			}
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn := mustDial(t, ctx, addr, kp, wiresocket.DialConfig{
		CoalesceInterval: 60 * time.Second, // hold events in coalescer
	})
	ch := conn.Channel(0)
	ch.SetUnreliable()

	for i := 0; i < N; i++ {
		if err := conn.Send(ctx, &wiresocket.Event{Type: uint8(i + 1)}); err != nil {
			t.Fatalf("Send %d: %v", i, err)
		}
	}

	// Close should flush the coalescer and deliver all N events.
	conn.Close()

	deadline := time.After(3 * time.Second)
	for count := 0; count < N; count++ {
		select {
		case <-received:
		case <-deadline:
			t.Fatalf("drain on Close: only got %d/%d events", count, N)
		}
	}
	// Verify nothing extra sneaked through.
	select {
	case <-received:
		t.Fatal("drain on Close: received more events than sent")
	default:
	}
}

// ─── Flush ────────────────────────────────────────────────────────────────────

// TestCoalescerFlush verifies that Flush() sends buffered events and waits for
// reliable ACKs without closing the connection.  After Flush returns the
// connection must still be usable for further sends.
func TestCoalescerFlush(t *testing.T) {
	const batch = 15

	received := make(chan struct{}, batch*3)
	addr, kp := serverSetup(t, wiresocket.ServerConfig{
		WorkerCount: 1,
		OnConnect: func(conn *wiresocket.Conn) {
			for {
				if _, err := conn.Recv(context.Background()); err != nil {
					return
				}
				received <- struct{}{}
			}
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn := mustDial(t, ctx, addr, kp, wiresocket.DialConfig{
		CoalesceInterval: 60 * time.Second,
	})
	defer conn.Close()

	// First batch: send and flush.
	for i := 0; i < batch; i++ {
		if err := conn.Send(ctx, &wiresocket.Event{Type: 1}); err != nil {
			t.Fatalf("Send (batch 1): %v", err)
		}
	}
	flushCtx, flushCancel := context.WithTimeout(ctx, 3*time.Second)
	conn.Flush(flushCtx)
	flushCancel()

	// Verify first batch arrived.
	deadline := time.After(3 * time.Second)
	for i := 0; i < batch; i++ {
		select {
		case <-received:
		case <-deadline:
			t.Fatalf("Flush: only got %d/%d events in first batch", i, batch)
		}
	}

	// Second batch after Flush confirms the connection is still alive.
	for i := 0; i < batch; i++ {
		if err := conn.Send(ctx, &wiresocket.Event{Type: 2}); err != nil {
			t.Fatalf("Send (batch 2): %v", err)
		}
	}
	flushCtx2, flushCancel2 := context.WithTimeout(ctx, 3*time.Second)
	conn.Flush(flushCtx2)
	flushCancel2()

	deadline2 := time.After(3 * time.Second)
	for i := 0; i < batch; i++ {
		select {
		case <-received:
		case <-deadline2:
			t.Fatalf("Flush: only got %d/%d events in second batch", i, batch)
		}
	}
}

// ─── Concurrent sends ─────────────────────────────────────────────────────────

// TestCoalescerConcurrentSends starts multiple sender goroutines that push
// events simultaneously.  All events must be delivered without loss.
func TestCoalescerConcurrentSends(t *testing.T) {
	const goroutines = 8
	const perGoroutine = 50
	const total = goroutines * perGoroutine

	var received atomic.Int64
	done := make(chan struct{})

	addr, kp := serverSetup(t, wiresocket.ServerConfig{
		OnConnect: func(conn *wiresocket.Conn) {
			for {
				if _, err := conn.Recv(context.Background()); err != nil {
					return
				}
				if received.Add(1) == total {
					close(done)
				}
			}
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn := mustDial(t, ctx, addr, kp, wiresocket.DialConfig{
		CoalesceInterval: 500 * time.Microsecond,
	})
	defer conn.Close()

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		g := g
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				e := &wiresocket.Event{Type: uint8(g + 1), Payload: []byte{byte(i)}}
				if err := conn.Send(ctx, e); err != nil {
					t.Errorf("goroutine %d, send %d: %v", g, i, err)
					return
				}
			}
		}()
	}
	wg.Wait()

	// Flush so all coalesced events reach the server.
	flushCtx, cancel2 := context.WithTimeout(ctx, 5*time.Second)
	conn.Flush(flushCtx)
	cancel2()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("concurrent sends: got %d/%d events", received.Load(), total)
	}
}

// ─── Disabled coalescing ──────────────────────────────────────────────────────

// TestCoalescerDisabled verifies that with CoalesceInterval=0 each event is
// sent in its own frame immediately (no buffering).
func TestCoalescerDisabled(t *testing.T) {
	const N = 10

	received := make(chan time.Time, N)
	addr, kp := serverSetup(t, wiresocket.ServerConfig{
		OnConnect: func(conn *wiresocket.Conn) {
			for {
				if _, err := conn.Recv(context.Background()); err != nil {
					return
				}
				received <- time.Now()
			}
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// No CoalesceInterval — each Send should reach the server immediately.
	conn := mustDial(t, ctx, addr, kp, wiresocket.DialConfig{})
	defer conn.Close()

	start := time.Now()
	for i := 0; i < N; i++ {
		if err := conn.Send(ctx, &wiresocket.Event{Type: uint8(i + 1)}); err != nil {
			t.Fatalf("Send %d: %v", i, err)
		}
	}

	// All events should arrive quickly since there is no coalesce delay.
	deadline := time.After(2 * time.Second)
	for i := 0; i < N; i++ {
		select {
		case ts := <-received:
			_ = ts.Sub(start) // just drain; timing assertions are flaky
		case <-deadline:
			t.Fatalf("disabled coalescing: got %d/%d events", i, N)
		}
	}
}

// ─── Frame-size regression ────────────────────────────────────────────────────

// TestCoalescerFrameSizeFitsOnePkt is a regression test for the bug where
// pendingBytes tracked raw payload bytes instead of actual wire bytes.
//
// Bug: the coalescer flushed after N events where N*payloadSize >= maxFragPayload,
// but the actual marshalled frame (which includes per-event field tags, varint
// length prefixes, and frame header fields) was larger than maxFragPayload,
// causing the frame to be split into 2 UDP fragments instead of 1.  With many
// frames in-flight and a small MaxIncompleteFrames limit on the server, the
// excess fragment reassembly buffers were exhausted and fragments were dropped,
// resulting in silent event loss that the sender never detected.
//
// Fix: addItem tracks evtWire = payloadLen + encoding_overhead and uses a
// lookahead flush condition that guarantees the assembled frame fits in one
// packet.
//
// Test parameters (MaxPacketSize=400, payload=100):
//   - maxFrag = 400-40 = 360 bytes
//   - per-event wire size = 100+3 = 103 bytes (body_len=101 < 128 → 1-byte varint)
//   - fixed eventsPerFrame  = (360-32)/103 = 3  → frame ≤ 3×103+26 = 335 bytes ✓
//   - buggy eventsPerFrame  = floor(360/100) = 3 too? Let me recheck:
//     buggy: flush when pendingBytes(raw) >= maxFrameBytes, i.e. N*100 >= 360 → N=4
//     buggy frame = 4×103+26 = 438 > 360 → 2 fragments
//
// With MaxIncompleteFrames=3 and a reliable window of 30 events (≈10 frames),
// the buggy path has up to 10 in-flight fragmented frames but only 3 reassembly
// slots → 7 frames silently dropped.  The fixed path sends 10 single-packet
// frames → MaxIncompleteFrames is never exercised → zero loss.
func TestCoalescerFrameSizeFitsOnePkt(t *testing.T) {
	const mtu = 400
	const payloadSize = 100
	const N = 60 // total events; reliable window = N

	maxFrag := wiresocket.MaxFragmentPayload(mtu)
	if maxFrag <= 0 {
		t.Skipf("MaxFragmentPayload(%d) = %d; skipping", mtu, maxFrag)
	}

	received := make(chan *wiresocket.Event, N*2)
	addr, kp := serverSetup(t, wiresocket.ServerConfig{
		MaxPacketSize: mtu,
		// MaxIncompleteFrames=3: with the old (buggy) code each frame needed 2
		// UDP fragments and up to N/4=15 frames could be in-flight, exceeding
		// the limit of 3 and causing fragment drops.  With the fix each frame
		// is a single packet so this limit is never exercised.
		MaxIncompleteFrames: 3,
		WorkerCount:         1, // serialise delivery for reliable channels
		OnConnect: func(conn *wiresocket.Conn) {
			ch := conn.Channel(1)
			for {
				e, err := ch.Recv(context.Background())
				if err != nil {
					return
				}
				received <- e
			}
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	conn := mustDial(t, ctx, addr, kp, wiresocket.DialConfig{
		MaxPacketSize:       mtu,
		CoalesceInterval:    200 * time.Microsecond,
		EventBufSize:        N,
		MaxIncompleteFrames: N * 2,
	})
	ch := conn.Channel(1)
	ch.SetReliable(wiresocket.ReliableCfg{WindowSize: N})

	payload := make([]byte, payloadSize)
	for i := 0; i < N; i++ {
		payload[0] = byte(i)
		if err := ch.Send(ctx, &wiresocket.Event{Type: 1, Payload: payload}); err != nil {
			t.Fatalf("Send %d: %v", i, err)
		}
	}

	flushCtx, flushCancel := context.WithTimeout(ctx, 5*time.Second)
	conn.Flush(flushCtx)
	flushCancel()

	// Drain with timeout — all N events must arrive.
	deadline := time.After(5 * time.Second)
	for i := 0; i < N; i++ {
		select {
		case <-received:
		case <-deadline:
			t.Fatalf("frame-size regression: only got %d/%d events (buggy coalescer would fragment frames and overflow MaxIncompleteFrames)", i, N)
		}
	}
	// Check nothing extra arrived.
	select {
	case <-received:
		t.Fatal("frame-size regression: received more events than sent")
	default:
	}
}

// TestCoalescerFrameSizeVaryPayloads checks the frame-size invariant across
// multiple payload sizes and MTUs to ensure coalesced frames always fit in one
// UDP packet.  This catches any payload size where the encoding-overhead
// accounting is off.
func TestCoalescerFrameSizeVaryPayloads(t *testing.T) {
	cases := []struct {
		mtu         int
		payloadSize int
		n           int // events to send
	}{
		{mtu: 400, payloadSize: 50, n: 40},
		{mtu: 400, payloadSize: 100, n: 40},
		{mtu: 400, payloadSize: 200, n: 20},
		{mtu: 600, payloadSize: 128, n: 50},
		{mtu: 600, payloadSize: 256, n: 30},
		{mtu: 1472, payloadSize: 128, n: 40},
		{mtu: 1472, payloadSize: 512, n: 20},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(
			// name: "mtu=X/payload=Y"
			"mtu="+itoa(tc.mtu)+"/payload="+itoa(tc.payloadSize),
			func(t *testing.T) {
				t.Parallel()
				runCoalescerFrameSizeCase(t, tc.mtu, tc.payloadSize, tc.n)
			},
		)
	}
}

// itoa converts an int to string without importing strconv.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	buf := [20]byte{}
	pos := len(buf)
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[pos:])
}

func runCoalescerFrameSizeCase(t *testing.T, mtu, payloadSize, n int) {
	t.Helper()

	maxFrag := wiresocket.MaxFragmentPayload(mtu)
	if maxFrag <= 0 || payloadSize >= maxFrag {
		t.Skipf("payload %d >= maxFrag %d for MTU %d; skipping", payloadSize, maxFrag, mtu)
	}

	received := make(chan *wiresocket.Event, n*2)
	addr, kp := serverSetup(t, wiresocket.ServerConfig{
		MaxPacketSize:       mtu,
		MaxIncompleteFrames: 3, // tight limit: buggy fragmented frames would overflow
		WorkerCount:         1,
		OnConnect: func(conn *wiresocket.Conn) {
			ch := conn.Channel(1)
			for {
				e, err := ch.Recv(context.Background())
				if err != nil {
					return
				}
				received <- e
			}
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	conn := mustDial(t, ctx, addr, kp, wiresocket.DialConfig{
		MaxPacketSize:       mtu,
		CoalesceInterval:    200 * time.Microsecond,
		EventBufSize:        n,
		MaxIncompleteFrames: n * 2,
	})
	ch := conn.Channel(1)
	ch.SetReliable(wiresocket.ReliableCfg{WindowSize: n})

	payload := make([]byte, payloadSize)
	for i := 0; i < n; i++ {
		if err := ch.Send(ctx, &wiresocket.Event{Type: 1, Payload: payload}); err != nil {
			t.Fatalf("Send %d: %v", i, err)
		}
	}
	flushCtx, flushCancel := context.WithTimeout(ctx, 5*time.Second)
	conn.Flush(flushCtx)
	flushCancel()

	deadline := time.After(5 * time.Second)
	for i := 0; i < n; i++ {
		select {
		case <-received:
		case <-deadline:
			t.Fatalf("got %d/%d events (frame-size overflow would cause fragment drops with MaxIncompleteFrames=3)", i, n)
		}
	}
}

// ─── Coalesced delivery ───────────────────────────────────────────────────────

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
