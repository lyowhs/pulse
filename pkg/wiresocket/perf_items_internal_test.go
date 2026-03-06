package wiresocket

// perf_items_internal_test.go — unit tests and benchmarks for performance
// items 6 (ackBatcher), 7 (atomic ackDirty), 8 (single-pass UnmarshalFrame),
// and 9 (lazy time.Now).
//
// Tests in this file are in package wiresocket (internal) so they can access
// unexported fields directly.

import (
	"testing"
	"time"
)

// ── Item 7: Atomic ackDirty fast-path in preSend ─────────────────────────────

// TestAckDirtyAtomicFastPath verifies that preSend piggybacks an ACK when
// ackDirty is true, and skips the recvMu acquisition when ackDirty is false.
func TestAckDirtyAtomicFastPath(t *testing.T) {
	t.Parallel()

	_, rs := makeTestChannelWithCfg(32, ReliableCfg{
		WindowSize: 16,
		ACKDelay:   0,
	})

	// Seed some receive state so the piggybacked ACK has meaningful values.
	rs.recvMu.Lock()
	rs.expectSeq = 5
	rs.ooo = 0b110 // SACK: frames 6 and 7 received
	rs.ackDirty.Store(true)
	rs.recvMu.Unlock()

	// Build a minimal frame for preSend.
	e := &Event{Type: 1, Payload: []byte("hi")}
	sf := getSingleEventFrame(0, e)
	frame := &sf.f

	// preSend must piggyback the ACK.
	rs.sendMu.Lock()
	rs.peerWindow = 16
	rs.sendMu.Unlock()
	if err := rs.preSend(frame, sf); err != nil {
		t.Fatalf("preSend: %v", err)
	}
	if frame.AckSeq != 5 {
		t.Errorf("piggybacked AckSeq: got %d, want 5", frame.AckSeq)
	}
	if frame.AckBitmap != 0b110 {
		t.Errorf("piggybacked AckBitmap: got %d, want 0b110", frame.AckBitmap)
	}
	if rs.ackDirty.Load() {
		t.Error("ackDirty should be false after piggybacking")
	}

	// A second preSend with ackDirty=false must NOT populate ACK fields.
	e2 := &Event{Type: 2, Payload: []byte("world")}
	sf2 := getSingleEventFrame(0, e2)
	frame2 := &sf2.f
	if err := rs.preSend(frame2, sf2); err != nil {
		t.Fatalf("preSend2: %v", err)
	}
	if frame2.AckSeq != 0 {
		t.Errorf("no piggyback expected: AckSeq=%d", frame2.AckSeq)
	}
}

// BenchmarkPreSendAckDirtyFalse measures the preSend fast-path cost when
// ackDirty is false (no ACK to piggyback — common case for send-only channels).
// With the atomic optimization (item 7), recvMu is not acquired on this path.
//
// The benchmark keeps the ring from filling up by ACKing each frame immediately
// after preSend so the window never blocks.
func BenchmarkPreSendAckDirtyFalse(b *testing.B) {
	_, rs := makeTestChannelWithCfg(defaultReliableWindow, ReliableCfg{
		WindowSize: defaultReliableWindow,
		ACKDelay:   0,
	})
	rs.sendMu.Lock()
	rs.peerWindow = defaultReliableWindow
	rs.sendMu.Unlock()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		e := &Event{Type: 1}
		sf := getSingleEventFrame(0, e)
		frame := &sf.f
		if err := rs.preSend(frame, sf); err != nil {
			b.Fatalf("preSend: %v", err)
		}
		// ACK immediately to keep the window open.
		rs.onAck(frame.Seq+1, 0, uint32(defaultReliableWindow))
	}
}

// BenchmarkPreSendAckDirtyTrue measures the preSend cost when ackDirty is true
// (ACK is piggybacked on every send — bidirectional channel).
func BenchmarkPreSendAckDirtyTrue(b *testing.B) {
	ch, rs := makeTestChannelWithCfg(defaultReliableWindow, ReliableCfg{
		WindowSize: defaultReliableWindow,
		ACKDelay:   0,
	})
	rs.sendMu.Lock()
	rs.peerWindow = defaultReliableWindow
	rs.sendMu.Unlock()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		// Set ackDirty before each preSend to simulate bidirectional traffic.
		rs.recvMu.Lock()
		rs.ackDirty.Store(true)
		rs.expectSeq = uint32(i + 1)
		rs.lastAdvWindow = uint32(cap(ch.events)) // suppress windowWatch
		rs.recvMu.Unlock()

		e := &Event{Type: 1}
		sf := getSingleEventFrame(0, e)
		frame := &sf.f
		if err := rs.preSend(frame, sf); err != nil {
			b.Fatalf("preSend: %v", err)
		}
		// ACK immediately to keep the window open.
		rs.onAck(frame.Seq+1, 0, uint32(defaultReliableWindow))
	}
}

// ── Item 6: ackBatcher replaces per-channel time.AfterFunc ───────────────────

// TestAckBatcherSendsACK verifies that the ackBatcher eventually clears
// ackDirty for a channel (by calling sendACK, which sets ackDirty=false even
// though the session is nil and the UDP send is a no-op).
func TestAckBatcherSendsACK(t *testing.T) {
	t.Parallel()

	// Create a Conn with a real ackBatcher but no session.
	conn := &Conn{done: make(chan struct{})}
	ch := newChannel(0, conn, 32)
	conn.ch0 = ch
	conn.channelMap.Store(uint16(0), ch)
	ch.SetReliable(ReliableCfg{WindowSize: 16, ACKDelay: 5 * time.Millisecond})
	rs := ch.reliable.Load()
	conn.ackBatcher = newAckBatcher(conn)
	defer close(conn.done)

	// Simulate an incoming frame: set ackDirty.
	rs.recvMu.Lock()
	rs.ackDirty.Store(true)
	rs.recvMu.Unlock()

	// Wait at most 3× defaultACKDelay for the batcher to fire and clear ackDirty.
	deadline := time.Now().Add(3 * defaultACKDelay)
	for time.Now().Before(deadline) {
		if !rs.ackDirty.Load() {
			return // batcher fired, test passes
		}
		time.Sleep(time.Millisecond)
	}
	t.Errorf("ackDirty still true after %v; batcher did not fire", 3*defaultACKDelay)
}

// BenchmarkAckBatcherSendPendingACKs measures the cost of one batcher tick
// with N channels, each with ackDirty=true.  Simulates the worst case where
// all channels receive frames simultaneously and the batcher fires.
func BenchmarkAckBatcherSendPendingACKs(b *testing.B) {
	const numChannels = 100

	conn := &Conn{done: make(chan struct{})}
	defer close(conn.done)

	// Create N channels, all with ackDirty=true and no session (sendACK no-ops).
	for i := uint16(0); i < numChannels; i++ {
		ch := newChannel(i, conn, 32)
		if i == 0 {
			conn.ch0 = ch
		}
		conn.channelMap.Store(i, ch)
		ch.SetReliable(ReliableCfg{WindowSize: 16, ACKDelay: defaultACKDelay})
		rs := ch.reliable.Load()
		rs.recvMu.Lock()
		rs.ackDirty.Store(true)
		rs.recvMu.Unlock()
	}

	batcher := &ackBatcher{conn: conn}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		// Re-dirty all channels before each tick.
		conn.channelMap.Range(func(_, v any) bool {
			ch := v.(*Channel)
			if rs := ch.reliable.Load(); rs != nil {
				rs.ackDirty.Store(true)
			}
			return true
		})
		batcher.sendPendingACKs()
	}
}

// ── Item 8: Single-pass UnmarshalFrame ───────────────────────────────────────

// BenchmarkUnmarshalFrameSingleEvent measures decoding a frame with 1 event —
// the common direct-send path (no coalescing).
func BenchmarkUnmarshalFrameSingleEvent(b *testing.B) {
	f := &Frame{
		ChannelId: 1,
		Seq:       42,
		AckSeq:    41,
		WindowSize: 256,
		Events: []*Event{{Type: 7, Payload: make([]byte, 128)}},
	}
	wire := f.Marshal()
	b.SetBytes(int64(len(wire)))
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := UnmarshalFrame(wire); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkUnmarshalFrameManyEvents measures decoding a coalesced frame with
// 32 events of 64-byte payload each — the hot receive path.
func BenchmarkUnmarshalFrameManyEvents(b *testing.B) {
	events := make([]*Event, 32)
	for i := range events {
		events[i] = &Event{Type: uint8(i), Payload: make([]byte, 64)}
	}
	f := &Frame{ChannelId: 1, Seq: 100, AckSeq: 99, WindowSize: 256, Events: events}
	wire := f.Marshal()
	b.SetBytes(int64(len(wire)))
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := UnmarshalFrame(wire); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkUnmarshalFrameACKOnly measures the standalone ACK frame path —
// no events, only reliability fields.
func BenchmarkUnmarshalFrameACKOnly(b *testing.B) {
	f := &Frame{ChannelId: 0, AckSeq: 1000, AckBitmap: 0xDEAD, WindowSize: 512}
	wire := f.Marshal()
	b.SetBytes(int64(len(wire)))
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := UnmarshalFrame(wire); err != nil {
			b.Fatal(err)
		}
	}
}

// ── Item 9: Lazy time.Now() updates ──────────────────────────────────────────

// TestTouchLastSendLazy verifies that touchLastSend skips the atomic store
// when called within lazyTimeThreshold of the last update.
func TestTouchLastSendLazy(t *testing.T) {
	t.Parallel()

	s := &session{}
	now := time.Now().UnixNano()
	s.lastSend.Store(now)

	// Call touchLastSend immediately: should NOT update (< 1ms elapsed).
	s.touchLastSend()
	if got := s.lastSend.Load(); got != now {
		t.Errorf("touchLastSend updated lastSend within threshold: got %d, want %d", got, now)
	}
}

// TestTouchLastSendUpdatesAfterThreshold verifies that touchLastSend stores a
// new timestamp once lazyTimeThreshold has elapsed.
func TestTouchLastSendUpdatesAfterThreshold(t *testing.T) {
	t.Parallel()

	s := &session{}
	// Set lastSend to 2ms in the past so the threshold is exceeded.
	past := time.Now().Add(-2 * time.Millisecond).UnixNano()
	s.lastSend.Store(past)

	s.touchLastSend()
	if got := s.lastSend.Load(); got == past {
		t.Error("touchLastSend did not update lastSend after threshold elapsed")
	}
}

// TestTouchLastRecvLazy verifies that touchLastRecv(false) and touchLastRecv(true)
// respect lazyTimeThreshold for both lastRecv and lastDataRecv.
func TestTouchLastRecvLazy(t *testing.T) {
	t.Parallel()

	s := &session{}
	now := time.Now().UnixNano()
	s.lastRecv.Store(now)
	s.lastDataRecv.Store(now)

	// Immediate call — within threshold, must NOT update.
	s.touchLastRecv(true)
	if got := s.lastRecv.Load(); got != now {
		t.Errorf("touchLastRecv updated lastRecv within threshold: got %d, want %d", got, now)
	}
	if got := s.lastDataRecv.Load(); got != now {
		t.Errorf("touchLastRecv updated lastDataRecv within threshold: got %d, want %d", got, now)
	}

	// After threshold: must update.
	past := time.Now().Add(-2 * time.Millisecond).UnixNano()
	s.lastRecv.Store(past)
	s.lastDataRecv.Store(past)
	s.touchLastRecv(true)

	if s.lastRecv.Load() == past {
		t.Error("touchLastRecv did not update lastRecv after threshold")
	}
	if s.lastDataRecv.Load() == past {
		t.Error("touchLastRecv did not update lastDataRecv after threshold")
	}
}

// TestTouchLastRecvDataFalse verifies that touchLastRecv(false) does not
// update lastDataRecv, even after the threshold.
func TestTouchLastRecvDataFalse(t *testing.T) {
	t.Parallel()

	s := &session{}
	past := time.Now().Add(-2 * time.Millisecond).UnixNano()
	s.lastRecv.Store(past)
	s.lastDataRecv.Store(past)

	s.touchLastRecv(false) // keepalive — must not touch lastDataRecv

	if s.lastDataRecv.Load() != past {
		t.Error("touchLastRecv(false) should not update lastDataRecv")
	}
	if s.lastRecv.Load() == past {
		t.Error("touchLastRecv(false) should update lastRecv after threshold")
	}
}

// BenchmarkTouchLastSend measures the cost of the lazy timestamp update at
// the two key points: within-threshold (common case, no store) and after
// threshold (store occurs).
func BenchmarkTouchLastSendWithinThreshold(b *testing.B) {
	s := &session{}
	s.lastSend.Store(time.Now().UnixNano())
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		s.touchLastSend()
	}
}

func BenchmarkTouchLastSendAfterThreshold(b *testing.B) {
	s := &session{}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		// Simulate > 1ms gap so the store always fires.
		s.lastSend.Store(time.Now().Add(-2 * time.Millisecond).UnixNano())
		s.touchLastSend()
	}
}
