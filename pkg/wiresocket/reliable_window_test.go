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
