package wiresocket

// reliable_window_test.go — unit tests for the sequenced window-update rule
// introduced in onAck to prevent stale out-of-order ACK packets from
// permanently reducing peerWindow.
//
// Root cause (Mar 2026): multiple goroutines (notifyWindowIncreased, windowWatch,
// preSend piggyback) call sess.send() concurrently with the same AckSeq but
// different window values.  On a multi-CPU loopback the kernel can serialise
// those sendmsg calls in arbitrary order, so a larger-window packet can arrive
// first and then be overwritten by a smaller-window packet that was sent earlier.
// onAck previously set peerWindow = w unconditionally; if peerWindow dropped
// below numPending+evtCount without a cond.Broadcast, preSend blocked forever.
//
// Fix: TCP-style sequenced rule in onAck:
//   ackSeq > lastWindowAckSeq  → new receiver state, apply peerWindow = w
//   ackSeq == lastWindowAckSeq → same receiver state, only increase (take max)
//   ackSeq < lastWindowAckSeq  → stale packet, ignore window field entirely

import (
	"testing"
	"time"
)

// TestOnAckWindowNotDecreaseOnSameAckSeq is the primary regression test for
// the out-of-order window-update bug.  It verifies that when two ACK packets
// with the same AckSeq arrive (a scenario that occurs when notifyWindowIncreased
// and preSend's piggyback race), peerWindow takes the maximum rather than
// blindly adopting the later-arriving (smaller) value.
func TestOnAckWindowNotDecreaseOnSameAckSeq(t *testing.T) {
	t.Parallel()

	_, rs := makeTestChannelWithCfg(64, ReliableCfg{
		WindowSize: 10,
		ACKDelay:   0, // disable timer so it never sends on the nil session
	})

	// ── Round 1: first ACK for ackSeq=2 with window=8 ────────────────────────
	// ackSeq(2) > lastWindowAckSeq(0) → set lastWindowAckSeq=2, peerWindow=8.
	rs.onAck(2, 0, 8)
	if got := rs.peerWindow; got != 8 {
		t.Fatalf("after onAck(ackSeq=2, window=8): peerWindow=%d, want 8", got)
	}

	// ── Same ackSeq=2, smaller window=3 (simulates a reordered piggybacked ACK
	// that was sent before the window=8 standalone ACK) ──────────────────────
	// Must NOT decrease: same receiver state, window can only increase.
	rs.onAck(2, 0, 3)
	if got := rs.peerWindow; got != 8 {
		t.Errorf("after onAck(ackSeq=2, window=3): peerWindow=%d, want 8 (same AckSeq must not decrease)", got)
	}

	// ── Same ackSeq=2, larger window=10 ─────────────────────────────────────
	// Must increase: max(8, 10) = 10.
	rs.onAck(2, 0, 10)
	if got := rs.peerWindow; got != 10 {
		t.Errorf("after onAck(ackSeq=2, window=10): peerWindow=%d, want 10", got)
	}

	// ── Stale ackSeq=1 < lastWindowAckSeq=2 ──────────────────────────────────
	// Must be ignored: stale out-of-order packet; peerWindow stays 10.
	rs.onAck(1, 0, 5)
	if got := rs.peerWindow; got != 10 {
		t.Errorf("after onAck(ackSeq=1, window=5) [stale]: peerWindow=%d, want 10 (stale must be ignored)", got)
	}

	// ── New ackSeq=5 > lastWindowAckSeq=2 → window decrease IS allowed ──────
	// A new cumulative ACK means new events were received; the receiver's buffer
	// can legitimately be fuller now, so a smaller window must be honoured.
	rs.onAck(5, 0, 4)
	if got := rs.peerWindow; got != 4 {
		t.Errorf("after onAck(ackSeq=5, window=4): peerWindow=%d, want 4 (new AckSeq allows decrease)", got)
	}
}

// TestOnAckWindowZeroIsHonouredOnNewAckSeq verifies that a window=0 from a new
// cumulative ACK (ackSeq advanced) correctly blocks the sender, and that a
// subsequent window reopen on the same ackSeq is honoured.  This ensures the
// fix does not break legitimate back-pressure.
func TestOnAckWindowZeroIsHonouredOnNewAckSeq(t *testing.T) {
	t.Parallel()

	_, rs := makeTestChannelWithCfg(64, ReliableCfg{
		WindowSize: 8,
		ACKDelay:   0,
	})

	// Establish a window at ackSeq=3.
	rs.onAck(3, 0, 8)
	if got := rs.peerWindow; got != 8 {
		t.Fatalf("setup: peerWindow=%d, want 8", got)
	}

	// Receiver buffer fills on new events (ackSeq advances to 10): window=0.
	rs.onAck(10, 0, 0)
	if got := rs.peerWindow; got != 0 {
		t.Errorf("after onAck(ackSeq=10, window=0): peerWindow=%d, want 0 (full buffer must be honoured)", got)
	}

	// Stale retransmit of old ACK with large window must not reopen the window.
	rs.onAck(3, 0, 8)
	if got := rs.peerWindow; got != 0 {
		t.Errorf("after stale onAck(ackSeq=3, window=8): peerWindow=%d, want 0 (stale must not reopen)", got)
	}

	// Window reopens: same ackSeq=10 (receiver drained, sends window=8 update).
	rs.onAck(10, 0, 8)
	if got := rs.peerWindow; got != 8 {
		t.Errorf("after onAck(ackSeq=10, window=8): peerWindow=%d, want 8 (window reopen on same AckSeq)", got)
	}
}

// TestOnAckLastWindowAckSeqMonotonic verifies the full sequence of window
// update rules: new AckSeq applies unconditionally, same AckSeq takes max,
// stale AckSeq is ignored.
func TestOnAckLastWindowAckSeqMonotonic(t *testing.T) {
	t.Parallel()

	_, rs := makeTestChannelWithCfg(64, ReliableCfg{
		WindowSize: 16,
		ACKDelay:   0,
	})

	steps := []struct {
		ackSeq         uint32
		window         uint32
		wantPeerWin    int
		wantLastAckSeq uint32
	}{
		// First ACK ever: applies unconditionally.
		{ackSeq: 1, window: 16, wantPeerWin: 16, wantLastAckSeq: 1},
		// Advance: new AckSeq allows legitimate decrease.
		{ackSeq: 5, window: 4, wantPeerWin: 4, wantLastAckSeq: 5},
		// Same ackSeq=5, larger window: must take max (16 > 4).
		{ackSeq: 5, window: 16, wantPeerWin: 16, wantLastAckSeq: 5},
		// Stale ackSeq=3 (< 5): ignored; peerWin and lastAckSeq unchanged.
		{ackSeq: 3, window: 1, wantPeerWin: 16, wantLastAckSeq: 5},
		// Further advance.
		{ackSeq: 20, window: 12, wantPeerWin: 12, wantLastAckSeq: 20},
	}

	for _, step := range steps {
		rs.onAck(step.ackSeq, 0, step.window)
		if got := rs.peerWindow; got != step.wantPeerWin {
			t.Errorf("onAck(ackSeq=%d, window=%d): peerWindow=%d, want %d",
				step.ackSeq, step.window, got, step.wantPeerWin)
		}
		if got := rs.lastWindowAckSeq; got != step.wantLastAckSeq {
			t.Errorf("onAck(ackSeq=%d, window=%d): lastWindowAckSeq=%d, want %d",
				step.ackSeq, step.window, got, step.wantLastAckSeq)
		}
	}
}

// ── Item 2: oldestSeq tracking (O(freed) scan in onAck / earliestPendingLocked) ──

// TestOnAckOldestSeqAdvances verifies that oldestSeq is updated to ackSeq on
// every cumulative ACK so that subsequent scans start from the correct lower
// bound.
func TestOnAckOldestSeqAdvances(t *testing.T) {
	t.Parallel()

	_, rs := makeTestChannelWithCfg(64, ReliableCfg{
		WindowSize: 16,
		BaseRTO:    time.Hour, // prevent timer fires
		ACKDelay:   0,
	})

	// Verify initial state.
	if rs.oldestSeq != 1 {
		t.Fatalf("initial oldestSeq=%d, want 1", rs.oldestSeq)
	}

	// Inject 4 pending frames manually (seq 1..4).
	rs.sendMu.Lock()
	for seq := uint32(1); seq <= 4; seq++ {
		slot := &rs.pending[seq%uint32(len(rs.pending))]
		slot.seq = seq
		slot.used = true
		slot.evtCount = 1
		slot.sentAt = time.Now()
		slot.frame = &Frame{ChannelId: 0, Seq: seq, Events: []*Event{{Type: 1}}}
	}
	rs.nextSeq = 5
	rs.numPending = 4
	rs.rtoRunning = true
	rs.rtoTimer = time.AfterFunc(time.Hour, func() {}) // dummy; won't fire
	rs.sendMu.Unlock()

	// ACK frames 1 and 2 (ackSeq=3 means seq 1,2 received).
	rs.onAck(3, 0, 16)
	if rs.oldestSeq != 3 {
		t.Errorf("after onAck(3): oldestSeq=%d, want 3", rs.oldestSeq)
	}
	if rs.numPending != 2 {
		t.Errorf("after onAck(3): numPending=%d, want 2", rs.numPending)
	}

	// ACK frames 3 and 4 (ackSeq=5).
	rs.onAck(5, 0, 16)
	if rs.oldestSeq != 5 {
		t.Errorf("after onAck(5): oldestSeq=%d, want 5", rs.oldestSeq)
	}
	if rs.numPending != 0 {
		t.Errorf("after onAck(5): numPending=%d, want 0", rs.numPending)
	}
}

// TestOnAckStaleAckDoesNotRewindOldestSeq ensures that a stale cumulative ACK
// (ackSeq ≤ oldestSeq) does not rewind oldestSeq back, which would cause
// onAck's [oldestSeq, ackSeq) loop to scan a zero-length range or, worse, wrap.
func TestOnAckStaleAckDoesNotRewindOldestSeq(t *testing.T) {
	t.Parallel()

	_, rs := makeTestChannelWithCfg(32, ReliableCfg{
		WindowSize: 8,
		BaseRTO:    time.Hour,
		ACKDelay:   0,
	})

	// Advance oldestSeq to 5 via a legitimate ACK.
	rs.onAck(5, 0, 8)
	if rs.oldestSeq != 5 {
		t.Fatalf("setup: oldestSeq=%d, want 5", rs.oldestSeq)
	}

	// Send a stale ACK: ackSeq=3 < oldestSeq=5.
	rs.onAck(3, 0, 8)
	if rs.oldestSeq != 5 {
		t.Errorf("stale onAck(3): oldestSeq=%d, want 5 (must not rewind)", rs.oldestSeq)
	}
}

// TestEarliestPendingLockedScansOldestToNext verifies that earliestPendingLocked
// skips already-freed slots (those below oldestSeq) and returns the frame with
// the earliest sentAt within [oldestSeq, nextSeq).
func TestEarliestPendingLockedScansOldestToNext(t *testing.T) {
	t.Parallel()

	_, rs := makeTestChannelWithCfg(64, ReliableCfg{
		WindowSize: 8,
		BaseRTO:    time.Hour,
		ACKDelay:   0,
	})

	now := time.Now()

	// Manually insert 3 frames at seq 3, 4, 5 (simulating oldestSeq=3 after
	// frames 1,2 were freed by an earlier ACK).
	rs.sendMu.Lock()
	rs.oldestSeq = 3
	rs.nextSeq = 6
	for i, seq := range []uint32{3, 4, 5} {
		slot := &rs.pending[seq%uint32(len(rs.pending))]
		slot.seq = seq
		slot.used = true
		slot.evtCount = 1
		slot.sentAt = now.Add(time.Duration(i) * time.Millisecond) // seq 3 is oldest
	}
	rs.numPending = 3

	earliest := rs.earliestPendingLocked()
	rs.sendMu.Unlock()

	if earliest == nil {
		t.Fatal("earliestPendingLocked returned nil, want seq=3")
	}
	if earliest.seq != 3 {
		t.Errorf("earliestPendingLocked returned seq=%d, want 3", earliest.seq)
	}
}

// TestResetResetsOldestSeq verifies that reset() resets oldestSeq to 1
// alongside nextSeq so that the [oldestSeq, nextSeq) range is correct after
// reconnect.
func TestResetResetsOldestSeq(t *testing.T) {
	t.Parallel()

	_, rs := makeTestChannelWithCfg(32, ReliableCfg{
		WindowSize: 8,
		BaseRTO:    time.Hour,
		ACKDelay:   0,
	})

	// Advance oldestSeq via a cumulative ACK.
	rs.onAck(7, 0, 8)
	if rs.oldestSeq != 7 {
		t.Fatalf("setup: oldestSeq=%d, want 7", rs.oldestSeq)
	}

	rs.reset()

	rs.sendMu.Lock()
	gotOldest := rs.oldestSeq
	gotNext := rs.nextSeq
	rs.sendMu.Unlock()

	if gotOldest != 1 {
		t.Errorf("after reset: oldestSeq=%d, want 1", gotOldest)
	}
	if gotNext != 1 {
		t.Errorf("after reset: nextSeq=%d, want 1", gotNext)
	}
}

// BenchmarkOnAckSmallStep measures the cost of onAck when only one frame is
// freed per call (the common case at high frame rates).  With oldestSeq
// tracking the loop walks exactly 1 slot instead of the full ring.
func BenchmarkOnAckSmallStep(b *testing.B) {
	const windowSize = 4096
	_, rs := makeTestChannelWithCfg(windowSize+16, ReliableCfg{
		WindowSize: windowSize,
		BaseRTO:    time.Hour,
		ACKDelay:   time.Hour,
	})
	b.ReportAllocs()

	// Fill the ring with windowSize pending frames.
	rs.sendMu.Lock()
	for seq := uint32(1); seq <= windowSize; seq++ {
		slot := &rs.pending[seq%uint32(len(rs.pending))]
		slot.seq = seq
		slot.used = true
		slot.evtCount = 1
		slot.sentAt = time.Now()
	}
	rs.nextSeq = windowSize + 1
	rs.oldestSeq = 1
	rs.numPending = windowSize
	rs.rtoRunning = true
	rs.rtoTimer = time.AfterFunc(time.Hour, func() {})
	rs.sendMu.Unlock()

	b.ResetTimer()
	// Each iteration: ACK one frame (ackSeq advances by 1).
	// We wrap around mod windowSize so the benchmark can run b.N iterations.
	seq := uint32(1)
	for i := 0; i < b.N; i++ {
		next := seq + 1
		rs.onAck(next, 0, uint32(windowSize))
		// Re-insert the freed slot so numPending doesn't drop to 0.
		rs.sendMu.Lock()
		slot := &rs.pending[seq%uint32(len(rs.pending))]
		slot.seq = seq
		slot.used = true
		slot.evtCount = 1
		slot.sentAt = time.Now()
		rs.numPending++
		rs.sendMu.Unlock()
		seq = ((seq - 1 + 1) % uint32(windowSize)) + 1
	}
}
