package wiresocket_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"example.com/pulse/pulse/pkg/wiresocket"
)

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

// TestReliableCoalescedFrameNoLoss is a regression test for the window unit
// mismatch (Bug 1): the old code tracked numPending in frames while peerWindow
// was in events (from myWindow = cap−len of ch.events).  With coalescing active
// each frame carries multiple events; W "allowed frames" could inject
// W×eventsPerFrame events into a W-slot receive buffer, causing silent
// drop-oldest overflows that the sender misread as successful delivery.
//
// The fix counts numPending in events: preSend blocks when
// numPending+evtCount > peerWindow, keeping the receiver's buffer safe.
func TestReliableCoalescedFrameNoLoss(t *testing.T) {
	const N = 200 // total events; also used as WindowSize and EventBufSize

	receivedC := make(chan uint8, N)

	// WorkerCount=1 serialises onRecv so OOO gaps never exceed reliableOOOWindow.
	// EventBufSize=N so the server buffer can hold all N in-flight events.
	addr, kp := serverSetup(t, wiresocket.ServerConfig{
		WorkerCount:  1,
		EventBufSize: N,
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

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// CoalesceInterval batches multiple events per UDP frame, activating the
	// event-counting window code path that was previously broken.
	conn := mustDial(t, ctx, addr, kp, wiresocket.DialConfig{
		CoalesceInterval: 200 * time.Microsecond,
	})
	ch := conn.Channel(1)
	ch.SetReliable(wiresocket.ReliableCfg{
		// WindowSize=N matches EventBufSize so numPending never exceeds the
		// server's receive-buffer capacity when measured in events.
		WindowSize: N,
		ACKDelay:   5 * time.Millisecond,
	})

	// 100-byte payload: eventsPerFrame ≈ 15 at the default 1472-byte MTU.
	payload := make([]byte, 100)
	for i := 0; i < N; i++ {
		if err := ch.Send(ctx, &wiresocket.Event{Type: uint8(i % 251), Payload: payload}); err != nil {
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

	if r := ch.Retransmits(); r != 0 {
		t.Logf("note: %d retransmit(s) observed on loopback (unexpected)", r)
	}
}

// TestReliableEchoSmallWindowNoDeadlock is a regression test for the
// out-of-order window-update deadlock (Mar 2026).
//
// The bug: when the server's receive buffer fills up and then drains, multiple
// goroutines (notifyWindowIncreased in the echo goroutine, preSend piggyback in
// the coalescer goroutine, windowWatch timer) send window-update ACKs
// concurrently.  On a multi-CPU loopback the kernel can deliver them in any
// order; a stale smaller-window packet arriving last caused onAck to set
// peerWindow to the smaller value.  Since peerWindow decreased, cond.Broadcast
// was not called, leaving preSend blocked indefinitely.  With the echo goroutine
// idle and windowWatch stopped, there was no recovery — permanent deadlock.
//
// The fix (lastWindowAckSeq): for the same AckSeq, onAck takes the maximum of
// any competing window advertisements, so a reordered smaller-window packet
// cannot permanently reduce peerWindow.
//
// Test setup: EventBufSize=window forces repeated buffer-full/drain cycles; each
// cycle produces concurrent window-update sends on multiple CPU cores, exercising
// the race.  All N echoed events must arrive within the timeout; a deadlock would
// cause the drain loop to stall until the context expires, failing the test.
func TestReliableEchoSmallWindowNoDeadlock(t *testing.T) {
	const (
		window      = 8   // tiny EventBufSize — fills quickly, drains fast
		N           = 200 // many fill/drain cycles to exercise the race
		payloadSize = 512 // large enough to coalesce into multi-event frames
	)

	// WorkerCount=1: serialises onRecv so OOO gaps stay within window bounds.
	addr, kp := serverSetup(t, wiresocket.ServerConfig{
		WorkerCount:  1,
		EventBufSize: window,
		OnConnect: func(conn *wiresocket.Conn) {
			ch := conn.Channel(1)
			for {
				e, err := ch.Recv(context.Background())
				if err != nil {
					return
				}
				// Echo immediately: drains ch.events and triggers concurrent
				// notifyWindowIncreased + coalescer preSend window updates.
				if err := ch.Send(context.Background(), e); err != nil {
					return
				}
			}
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	conn := mustDial(t, ctx, addr, kp, wiresocket.DialConfig{
		CoalesceInterval: 200 * time.Microsecond,
	})
	defer conn.Close()

	ch := conn.Channel(1)
	ch.SetReliable(wiresocket.ReliableCfg{
		WindowSize: window,
		ACKDelay:   5 * time.Millisecond,
	})

	var rxCount atomic.Int64
	var rxDone sync.WaitGroup
	rxDone.Add(1)
	go func() {
		defer rxDone.Done()
		evCh := ch.Events()
		for {
			select {
			case <-evCh:
				// Drain all available events — the signal channel (cap=1)
				// coalesces multiple pushes into one signal.
				for {
					if _, ok := ch.PopEvent(); !ok {
						break
					}
					rxCount.Add(1)
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	payload := make([]byte, payloadSize)
	for i := 0; i < N; i++ {
		if err := ch.Send(ctx, &wiresocket.Event{Type: uint8(i % 251), Payload: payload}); err != nil {
			t.Fatalf("Send[%d]: %v", i, err)
		}
	}

	// Flush must complete — a deadlock would block here until the 10s timeout.
	flushCtx, flushCancel := context.WithTimeout(ctx, 10*time.Second)
	conn.Flush(flushCtx)
	flushCancel()

	// Drain: wait for all N echoes to arrive.  A stuck peerWindow would stall
	// the echo return path, causing this loop to time out.
	drainDeadline := time.Now().Add(10 * time.Second)
	for rxCount.Load() < N && time.Now().Before(drainDeadline) {
		time.Sleep(5 * time.Millisecond)
	}

	cancel()
	rxDone.Wait()

	if got := rxCount.Load(); got != N {
		t.Errorf("echo drain: received %d/%d events (peerWindow deadlock or event loss)", got, N)
	}
}
