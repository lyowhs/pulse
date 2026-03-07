package wiresocket

import (
	"log/slog"
	"sync/atomic"
)

// debugLog holds the package-level debug logger. nil means disabled (default).
var debugLog atomic.Pointer[slog.Logger]

// Diagnostic counters — zero-overhead when not read.
// These counters are incremented at key failure points in the protocol stack
// and can be read by benchmarks to identify root causes of packet loss.
var (
	// DebugFlushLoopErrors counts the number of times flushLoop encountered
	// a write error and closed the session.  Non-zero means the sender goroutine
	// hit a fatal UDP send error (e.g. ECONNREFUSED, EPERM) on a session.
	DebugFlushLoopErrors atomic.Int64

	// DebugDataDroppedClosed counts packets dropped because the target session
	// was found in the routing table but already closed (sess.isDone()).
	DebugDataDroppedClosed atomic.Int64

	// DebugDataDroppedUnknown counts packets dropped because the target session
	// index was not found in the routing table.
	DebugDataDroppedUnknown atomic.Int64

	// DebugWorkerQueueFull counts incoming packets dropped because the worker
	// channel was full (s.work was at capacity).
	DebugWorkerQueueFull atomic.Int64

	// DebugRingDropped counts events dropped because the channel ring buffer
	// was full.  For reliable channels, flow control should prevent this;
	// non-zero values indicate a bug in the window-size calculation.
	DebugRingDropped atomic.Int64

	// DebugOOOTooFar counts reliable frames dropped because the sequence gap
	// exceeded reliableOOOWindow.  Non-zero values indicate the sender's
	// in-flight window exceeds the receiver's OOO buffer.
	DebugOOOTooFar atomic.Int64

	// DebugProbesFired counts how many times the zero-window probe goroutine
	// successfully sent a probe frame (sess != nil).  Useful for diagnosing
	// flow-control deadlocks in the reliable send path.
	DebugProbesFired atomic.Int64

	// DebugOnAckNoUnblock counts how many times onAck ran but neither freed
	// any frames nor increased peerWindow, so cond.Broadcast was not called.
	// Non-zero means ACKs are arriving but not unblocking preSend.
	DebugOnAckNoUnblock atomic.Int64

	// DebugPreSendBlocked counts how many times preSend entered the wait loop
	// (numPending+evtCount > peerWindow at least once).
	DebugPreSendBlocked atomic.Int64

	// DebugEventsDelivered counts the total events successfully pushed to
	// any channel's ring by deliverEventToChannel or the unreliable path.
	DebugEventsDelivered atomic.Int64

	// DebugOnRecvDuplicate counts frames dropped in onRecv because seq < expectSeq.
	DebugOnRecvDuplicate atomic.Int64

	// DebugOnRecvInOrder counts frames delivered in-order by onRecv (seq == expectSeq).
	DebugOnRecvInOrder atomic.Int64

	// DebugSessionReceiveCalls counts how many times sess.receive() is called
	// (i.e. typeData packets read by the client read loop).
	DebugSessionReceiveCalls atomic.Int64

	// DebugReplayRejected counts packets rejected by the replay window.
	DebugReplayRejected atomic.Int64

	// DebugRetransmitFired counts how many times retransmit() ran (passed
	// epoch, inFlight, and numPending checks) and scanned the pending ring.
	DebugRetransmitFired atomic.Int64

	// DebugRetransmitBatchEmpty counts retransmit() invocations that found
	// no expired frames (all sentAt still within the RTO window).
	DebugRetransmitBatchEmpty atomic.Int64

	// DebugRetransmitSent counts individual frames re-sent by retransmit().
	// Incremented once per sess.send call inside the retransmit batch loop.
	DebugRetransmitSent atomic.Int64

	// DebugRetransmitSessNil counts frames skipped in retransmit() because
	// sessionFast() returned nil (session not yet established).
	DebugRetransmitSessNil atomic.Int64

	// DebugRetransmitInFlight counts retransmit() calls skipped because a
	// previous retransmit goroutine was still executing (retransmitInFlight=true).
	DebugRetransmitInFlight atomic.Int64

	// DebugRetransmitNumPendingZero counts retransmit() calls that returned
	// early because numPending == 0 (no frames in the pending ring).
	DebugRetransmitNumPendingZero atomic.Int64

	// DebugRetransmitEpochAbort counts retransmit() calls that self-aborted
	// because the captured epoch no longer matched rs.rtoEpoch (superseded
	// by a later armRetransmitLocked call).
	DebugRetransmitEpochAbort atomic.Int64

	// DebugRetransmitRearmSkipped counts times the re-arm at the end of
	// retransmit() was skipped because numPending==0 or rtoRunning==false.
	DebugRetransmitRearmSkipped atomic.Int64

	// DebugRetransmitSendErr counts how many times sess.send() returned a
	// non-nil error inside retransmit().
	DebugRetransmitSendErr atomic.Int64

	// DebugRTOTimerArmed counts each armRetransmitLocked() call (from
	// preSend, retransmit re-arm, and onAck freed path).
	DebugRTOTimerArmed atomic.Int64

	// DebugRTOTimerStopped counts each rtoTimer.Stop() call in onAck
	// (triggered when numPending == 0 after ACKing frames).
	DebugRTOTimerStopped atomic.Int64

	// DebugReliableReset counts each reliableState.reset() call.
	DebugReliableReset atomic.Int64

	// DebugCoalescerPreSendFailed counts events dropped by the coalescer
	// because rs.preSend returned an error (channel/conn closed).
	DebugCoalescerPreSendFailed atomic.Int64

	// DebugCoalescerSendFailed counts events dropped by the coalescer
	// because sess.send returned an error after preSend succeeded.
	DebugCoalescerSendFailed atomic.Int64
)

// ResetDebugCounters zeroes all diagnostic counters.
func ResetDebugCounters() {
	DebugFlushLoopErrors.Store(0)
	DebugDataDroppedClosed.Store(0)
	DebugDataDroppedUnknown.Store(0)
	DebugWorkerQueueFull.Store(0)
	DebugRingDropped.Store(0)
	DebugOOOTooFar.Store(0)
	DebugProbesFired.Store(0)
	DebugOnAckNoUnblock.Store(0)
	DebugPreSendBlocked.Store(0)
	DebugEventsDelivered.Store(0)
	DebugOnRecvDuplicate.Store(0)
	DebugOnRecvInOrder.Store(0)
	DebugSessionReceiveCalls.Store(0)
	DebugReplayRejected.Store(0)
	DebugRetransmitFired.Store(0)
	DebugRetransmitBatchEmpty.Store(0)
	DebugRetransmitSent.Store(0)
	DebugRetransmitSessNil.Store(0)
	DebugRetransmitInFlight.Store(0)
	DebugRetransmitNumPendingZero.Store(0)
	DebugRetransmitEpochAbort.Store(0)
	DebugRetransmitRearmSkipped.Store(0)
	DebugRetransmitSendErr.Store(0)
	DebugRTOTimerArmed.Store(0)
	DebugRTOTimerStopped.Store(0)
	DebugReliableReset.Store(0)
	DebugCoalescerPreSendFailed.Store(0)
	DebugCoalescerSendFailed.Store(0)
}

// SetDebugLogger enables verbose protocol-level debug logging for all
// wiresocket operations in the current process.
//
// The provided logger receives [slog.LevelDebug] records for every protocol
// event: handshake state transitions, DH operations, packet send/receive,
// keepalives, session lifecycle, replay-window decisions, and errors.
//
// Pass nil to disable debug logging (the default).
func SetDebugLogger(l *slog.Logger) {
	debugLog.Store(l)
}

// dbg emits a single debug record.  It is a zero-allocation no-op when no
// debug logger has been configured.
func dbg(msg string, args ...any) {
	l := debugLog.Load()
	if l == nil {
		return
	}
	l.Debug(msg, args...)
}
