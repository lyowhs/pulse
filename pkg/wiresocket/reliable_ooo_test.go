package wiresocket

// Regression tests for the reliable OOO buffer.
//
// These tests live in the internal package (wiresocket, not wiresocket_test)
// so they can drive reliableState.onRecv directly without going through the
// full network stack.
//
// Root cause that prompted these tests:
//
//   reliableOOOWindow was 64, but the reliable send window is 256.  With
//   GOMAXPROCS server workers delivering frames concurrently, up to 256
//   frames can be in-flight simultaneously.  Any frame with
//     gap = seq - expectSeq > 64
//   was permanently dropped ("OOO frame too far ahead").  The sender
//   retransmitted one frame at a time (single RTO timer, BaseRTO=200 ms),
//   causing catastrophic throughput loss on the bench.
//
//   Fix: reliableOOOWindow raised to 256; drain condition changed from
//   ooo&1 != 0 (SACK bitmap, 64 bits wide) to oooFrames[0] != nil (frame
//   pointer), so the full 256-slot buffer is drained correctly.

import (
	"errors"
	"testing"
	"time"
)

// makeTestChannel creates a minimal Channel with reliableState for unit tests.
// The fake Conn has no session (sessionFast returns nil) so ACK timers fire
// and return harmlessly without sending anything on the wire.
func makeTestChannel(bufSize int) (*Channel, *reliableState) {
	conn := &Conn{done: make(chan struct{})}
	ch := newChannel(0, conn, bufSize)
	conn.ch0 = ch
	conn.channelMap.Store(uint16(0), ch)
	ch.SetReliable(ReliableCfg{WindowSize: 256})
	return ch, ch.reliable.Load()
}

// makeTestChannelWithCfg is like makeTestChannel but accepts a custom ReliableCfg.
func makeTestChannelWithCfg(bufSize int, cfg ReliableCfg) (*Channel, *reliableState) {
	conn := &Conn{done: make(chan struct{})}
	ch := newChannel(0, conn, bufSize)
	conn.ch0 = ch
	conn.channelMap.Store(uint16(0), ch)
	ch.SetReliable(cfg)
	return ch, ch.reliable.Load()
}

// makeFrame builds a minimal Frame carrying one Event whose Payload contains
// a single byte equal to byte(seq & 0xFF) so tests can verify ordering.
func makeOOOFrame(seq uint32) *Frame {
	return &Frame{
		ChannelId: 0,
		Seq:       seq,
		Events:    []*Event{{Type: 1, Payload: []byte{byte(seq & 0xFF)}}},
	}
}

// TestReliableOOOBeyond64 verifies that out-of-order frames whose gap exceeds
// the old 64-slot SACK bitmap width are correctly buffered and delivered.
//
// Before the fix (reliableOOOWindow=64) frames 65..130 would be permanently
// dropped ("OOO frame too far ahead"), leaving 65 events lost.
func TestReliableOOOBeyond64(t *testing.T) {
	t.Parallel()

	const total = 130 // > old reliableOOOWindow of 64, < new value of 256

	ch, rs := makeTestChannel(total + 16)

	// Deliver frames 2..total before frame 1.
	// Their gaps (1..total-1) span both within and beyond the 64-bit SACK window.
	for seq := uint32(2); seq <= total; seq++ {
		rs.onRecv(seq, makeOOOFrame(seq))
	}

	// No events should be in ch.events yet: frame 1 (expectSeq=1) hasn't arrived.
	if n := ch.ring.Len(); n != 0 {
		t.Fatalf("before frame 1: want 0 events in buffer, got %d", n)
	}

	// Deliver frame 1 — this should unlock and drain the entire OOO buffer.
	rs.onRecv(1, makeOOOFrame(1))

	// All total frames must now be in ch.events, delivered in order.
	if n := ch.ring.Len(); n != total {
		t.Fatalf("after frame 1: want %d events in buffer, got %d (lost %d)",
			total, n, total-n)
	}

	for i := 1; i <= total; i++ {
		e := ch.ring.mustPop()
		want := byte(i & 0xFF)
		if e.Payload[0] != want {
			t.Fatalf("event %d: payload byte = %d, want %d (out-of-order delivery)",
				i, e.Payload[0], want)
		}
	}
}

// TestReliableOOOFullWindow verifies that an entire reliableOOOWindow (256
// frames) can arrive out-of-order without any frame being dropped.
//
// Before the fix, only the first 64 would be buffered; frames 65..256 (192
// frames) would be silently dropped.
func TestReliableOOOFullWindow(t *testing.T) {
	t.Parallel()

	const total = reliableOOOWindow // 256 — the new OOO buffer size

	ch, rs := makeTestChannel(total + 16)

	// Deliver frames 2..total before frame 1.
	for seq := uint32(2); seq <= total; seq++ {
		rs.onRecv(seq, makeOOOFrame(seq))
	}

	// Nothing should be delivered yet.
	if n := ch.ring.Len(); n != 0 {
		t.Fatalf("before frame 1: want 0 events, got %d", n)
	}

	// Frame 1 unlocks the full window.
	rs.onRecv(1, makeOOOFrame(1))

	if n := ch.ring.Len(); n != total {
		t.Fatalf("after frame 1: want %d events, got %d (lost %d)",
			total, n, total-n)
	}

	// Verify in-order delivery.
	for i := 1; i <= total; i++ {
		e := ch.ring.mustPop()
		want := byte(i & 0xFF)
		if e.Payload[0] != want {
			t.Fatalf("event %d: payload byte = %d, want %d", i, e.Payload[0], want)
		}
	}
}

// TestReliableOOOWindowSize asserts that reliableOOOWindow >= defaultReliableWindow
// so that a full in-flight window of frames can always be buffered without loss.
// This is a static invariant test — it cannot fail at runtime if the constants
// are set correctly, but it makes the constraint explicit and catches future regressions.
func TestReliableOOOWindowSize(t *testing.T) {
	if reliableOOOWindow < defaultReliableWindow {
		t.Fatalf("reliableOOOWindow (%d) < defaultReliableWindow (%d): "+
			"OOO buffer too small — frames beyond slot %d will be dropped "+
			"when a full reliable window (%d frames) is in-flight",
			reliableOOOWindow, defaultReliableWindow,
			reliableOOOWindow, defaultReliableWindow)
	}
}

// TestReliableOOOSACKBitmapCoverage verifies that the SACK-bitmap-based fast
// path still works correctly for in-window gaps ≤ sackBitmapBits (64).
// These are the slots tracked in the ooo uint64 field.
func TestReliableOOOSACKBitmapCoverage(t *testing.T) {
	t.Parallel()

	const total = 64 // exactly one bitmap's worth

	ch, rs := makeTestChannel(total + 16)

	// Deliver frames 2..64 out of order — all within the SACK bitmap range.
	for seq := uint32(2); seq <= total; seq++ {
		rs.onRecv(seq, makeOOOFrame(seq))
	}

	if n := ch.ring.Len(); n != 0 {
		t.Fatalf("before frame 1: want 0 events, got %d", n)
	}

	// Deliver frame 1 — drain through the SACK bitmap path.
	rs.onRecv(1, makeOOOFrame(1))

	if n := ch.ring.Len(); n != total {
		t.Fatalf("after frame 1: want %d events, got %d", total, n)
	}
	for i := 1; i <= total; i++ {
		e := ch.ring.mustPop()
		if e.Payload[0] != byte(i&0xFF) {
			t.Fatalf("event %d: wrong payload", i)
		}
	}
}

// TestReliableOOOCircularBufferWrap verifies that the circular OOO buffer
// correctly wraps around after a full window of frames has been delivered.
//
// The fix (item 1 of the performance improvements) replaced the O(N) memmove
// in deliverInOrderLocked with an O(1) circular-buffer head increment.
// This test confirms that after draining a full window (oooHead wraps back
// to 0), the next round of OOO frames is stored and delivered at the correct
// circular slots.
func TestReliableOOOCircularBufferWrap(t *testing.T) {
	t.Parallel()

	const N = reliableOOOWindow
	// Buffer large enough to hold all events from one full round.
	ch, rs := makeTestChannel(N + 16)

	// Round 1: buffer frames 2..N+1 OOO, then deliver frame 1.
	// Delivering frame 1 triggers N+1 advances of oooHead:
	//   N advances for the N OOO frames drained, plus 1 for the nil
	//   termination (the loop always advances before checking nil).
	//   Result: (0 + N+1) % N = 1.
	for seq := uint32(2); seq <= uint32(N)+1; seq++ {
		rs.onRecv(seq, makeOOOFrame(seq))
	}
	if n := ch.ring.Len(); n != 0 {
		t.Fatalf("round 1 before frame 1: want 0 events, got %d", n)
	}
	rs.onRecv(1, makeOOOFrame(1))
	if n := ch.ring.Len(); n != N+1 {
		t.Fatalf("round 1 after frame 1: want %d events, got %d (lost %d)",
			N+1, n, N+1-n)
	}
	for i := 1; i <= N+1; i++ {
		e := ch.ring.mustPop()
		if e.Payload[0] != byte(i&0xFF) {
			t.Fatalf("round 1 event %d: payload=%d want=%d", i, e.Payload[0], byte(i&0xFF))
		}
	}

	// Confirm oooHead is at 1 (= (N+1) % N): N advances for OOO drains
	// plus 1 for the nil-termination advance.
	rs.recvMu.Lock()
	gotHead := rs.oooHead
	rs.recvMu.Unlock()
	wantHead := (N + 1) % N
	if gotHead != wantHead {
		t.Errorf("after round 1 full drain: oooHead=%d, want %d", gotHead, wantHead)
	}

	// Round 2: base = N+2 (current expectSeq after round 1).
	// Buffer N frames OOO, deliver the in-order base frame.
	// This exercises the circular buffer after a complete wrap.
	base := uint32(N + 2)
	for seq := base + 1; seq <= base+uint32(N)-1; seq++ {
		rs.onRecv(seq, makeOOOFrame(seq))
	}
	rs.onRecv(base, makeOOOFrame(base))
	if n := ch.ring.Len(); n != N {
		t.Fatalf("round 2: want %d events, got %d (lost %d)", N, n, N-n)
	}
	for i := 0; i < N; i++ {
		e := ch.ring.mustPop()
		wantSeq := base + uint32(i)
		if e.Payload[0] != byte(wantSeq&0xFF) {
			t.Fatalf("round 2 event %d: payload=%d want=%d", i, e.Payload[0], byte(wantSeq&0xFF))
		}
	}
}

// TestReliableOOOCircularSlotIndexing verifies that the circular slot formula
// (oooHead+gap-1)%N is correct for all gap values, including the boundary
// case gap=reliableOOOWindow (which maps to the slot just before oooHead).
func TestReliableOOOCircularSlotIndexing(t *testing.T) {
	t.Parallel()

	const N = reliableOOOWindow
	ch, rs := makeTestChannel(N + 16)

	// Store only the frame at the maximum gap (gap=N, slot=(oooHead+N-1)%N).
	// Then store gap=1..N-1 one at a time, verifying no collision.
	// Finally deliver the in-order frame and confirm all N are received.
	for seq := uint32(2); seq <= uint32(N)+1; seq++ {
		rs.onRecv(seq, makeOOOFrame(seq))
	}

	// Verify no premature delivery.
	if n := ch.ring.Len(); n != 0 {
		t.Fatalf("before in-order frame: want 0 events, got %d", n)
	}

	rs.onRecv(1, makeOOOFrame(1))
	if n := ch.ring.Len(); n != N+1 {
		t.Fatalf("after in-order frame: want %d events, got %d", N+1, n)
	}
	for i := 1; i <= N+1; i++ {
		e := ch.ring.mustPop()
		if e.Payload[0] != byte(i&0xFF) {
			t.Fatalf("event %d: out-of-order delivery (payload %d)", i, e.Payload[0])
		}
	}
}

// TestReliableOOOWindowSize asserts that reliableOOOWindow >= defaultReliableWindow for the unit mismatch
// in the reliable send window: the old code incremented numPending by 1 per
// frame regardless of how many events the frame carried.  When the window was
// measured in events (myWindow = cap-len of ch.events) but numPending counted
// frames, a coalesced sender could push far more events than the buffer held,
// triggering silent drop-oldest overflows that the receiver ACKed as delivered.
//
// The fix: numPending tracks total events in-flight (sum of evtCount per frame)
// and preSend blocks when numPending + evtCount > peerWindow.
func TestReliableWindowSizedInEvents(t *testing.T) {
	t.Parallel()

	// Window of 10 events; BaseRTO long so the retransmit timer does not
	// fire and interfere with the test.
	ch, rs := makeTestChannelWithCfg(64, ReliableCfg{
		WindowSize: 10,
		BaseRTO:    10 * time.Second,
	})

	// Frame 1: 3 events → numPending should become 3.
	f1 := &Frame{Events: []*Event{{Type: 1}, {Type: 2}, {Type: 3}}}
	if err := rs.preSend(f1, nil); err != nil {
		t.Fatalf("preSend f1: %v", err)
	}
	rs.sendMu.Lock()
	if rs.numPending != 3 {
		t.Errorf("after f1: numPending=%d, want 3", rs.numPending)
	}
	rs.sendMu.Unlock()

	// Frame 2: 5 events → numPending should become 8.
	f2 := &Frame{Events: []*Event{{Type: 4}, {Type: 5}, {Type: 6}, {Type: 7}, {Type: 8}}}
	if err := rs.preSend(f2, nil); err != nil {
		t.Fatalf("preSend f2: %v", err)
	}
	rs.sendMu.Lock()
	if rs.numPending != 8 {
		t.Errorf("after f2: numPending=%d, want 8", rs.numPending)
	}
	rs.sendMu.Unlock()

	// ACK both frames (ackSeq=3 means seq 1 and 2 have been received).
	// f1 had evtCount=3, f2 had evtCount=5; freed should equal 8.
	rs.onAck(3, 0, 10)
	rs.sendMu.Lock()
	if rs.numPending != 0 {
		t.Errorf("after onAck(ackSeq=3): numPending=%d, want 0", rs.numPending)
	}
	rs.sendMu.Unlock()

	// Frame 3: 2 events → numPending should become 2.
	f3 := &Frame{Events: []*Event{{Type: 9}, {Type: 10}}}
	if err := rs.preSend(f3, nil); err != nil {
		t.Fatalf("preSend f3: %v", err)
	}
	rs.sendMu.Lock()
	if rs.numPending != 2 {
		t.Errorf("after f3: numPending=%d, want 2", rs.numPending)
	}
	rs.sendMu.Unlock()

	// Drain: ACK frame 3 and close so the retransmit timer is stopped.
	rs.onAck(4, 0, 10)
	ch.closeLocal()
}

// TestReliableCloseUnblocksPreSend is a regression test for the missing
// cond.Broadcast() call in closeLocal().  The old code closed ch.done but
// never woke goroutines blocked in preSend's cond.Wait — they leaked forever.
//
// The fix adds rs.cond.Broadcast() inside closeLocal() so that any goroutine
// waiting for window space is immediately unblocked and returns ErrChannelClosed.
func TestReliableCloseUnblocksPreSend(t *testing.T) {
	t.Parallel()

	// WindowSize=2; we fill the window then verify the blocked sender unblocks
	// when the channel is closed.  BaseRTO=1h so the retransmit timer does not
	// interfere with the goroutine scheduling in this test.
	ch, rs := makeTestChannelWithCfg(8, ReliableCfg{
		WindowSize: 2,
		BaseRTO:    time.Hour,
	})

	// Fill the window: 2 single-event frames → numPending=2=peerWindow.
	for i := range 2 {
		f := &Frame{Events: []*Event{{Type: uint8(i)}}}
		if err := rs.preSend(f, nil); err != nil {
			t.Fatalf("preSend[%d]: %v", i, err)
		}
	}

	// The next send must block: numPending(2)+evtCount(1)=3 > peerWindow(2).
	errC := make(chan error, 1)
	go func() {
		f := &Frame{Events: []*Event{{Type: 99}}}
		errC <- rs.preSend(f, nil)
	}()

	// Give the goroutine time to enter cond.Wait.
	time.Sleep(20 * time.Millisecond)

	// Close the channel — must broadcast to wake the blocked preSend.
	ch.closeLocal()

	select {
	case err := <-errC:
		if !errors.Is(err, ErrChannelClosed) {
			t.Errorf("preSend returned %v, want ErrChannelClosed", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("preSend did not unblock after channel close (goroutine leak)")
	}
}

// ─── benchmarks ───────────────────────────────────────────────────────────────

// BenchmarkOOOInOrderDrain measures the time to drain a full OOO window when
// the in-order frame finally arrives.  This is the exact hot path improved by
// the O(N)→O(1) circular-buffer optimisation (item 1).
//
// Before the fix: each of the N OOO frames required a copy of the entire
// oooFrames array (32 KB for N=4096), totalling O(N²) memory traffic.
// After the fix: each drain step is a nil-check + slot clear + head increment,
// totalling O(N) work regardless of window size.
//
// Run with:
//
//	go test ./pkg/wiresocket/ -bench=BenchmarkOOOInOrderDrain -benchtime=5s -v
func BenchmarkOOOInOrderDrain(b *testing.B) {
	const N = reliableOOOWindow

	// Use a large ACKDelay and BaseRTO so timer goroutines do not fire and
	// interfere with benchmark timing.
	ch, rs := makeTestChannelWithCfg(N+16, ReliableCfg{
		WindowSize: N,
		BaseRTO:    time.Hour,
		ACKDelay:   time.Hour,
	})

	// Pre-build frame objects to avoid allocation noise in the timed section.
	oooFrames := make([]*Frame, N)
	for i := range oooFrames {
		oooFrames[i] = makeOOOFrame(uint32(i + 2)) // seq 2..N+1
	}
	inOrderFrame := makeOOOFrame(1)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Setup (not timed): reset recv-side state and pre-fill OOO buffer.
		b.StopTimer()
		rs.recvMu.Lock()
		rs.expectSeq = 1
		rs.ooo = 0
		rs.oooHead = 0
		for j := range rs.oooFrames {
			rs.oooFrames[j] = nil
		}
		rs.ackDirty.Store(false)
		rs.recvMu.Unlock()

		// Store N-1 OOO frames (seq 2..N+1) so the buffer is full.
		for _, f := range oooFrames {
			rs.onRecv(f.Seq, f)
		}
		// Drain events to prevent channel overflow on the next iteration.
		for ch.ring.Len() > 0 {
			ch.ring.mustPop()
		}
		b.StartTimer()

		// Timed: deliver the missing in-order frame, triggering a full
		// N-step OOO drain.  With the circular buffer this is O(N); with
		// the old shift-left it was O(N²).
		rs.onRecv(1, inOrderFrame)
		b.StopTimer()

		// Drain events before next iteration (not timed).
		for ch.ring.Len() > 0 {
			ch.ring.mustPop()
		}
	}
	b.ReportMetric(float64(N), "frames/op")
}
