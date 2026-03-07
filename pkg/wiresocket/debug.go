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
)

// ResetDebugCounters zeroes all diagnostic counters.
func ResetDebugCounters() {
	DebugFlushLoopErrors.Store(0)
	DebugDataDroppedClosed.Store(0)
	DebugDataDroppedUnknown.Store(0)
	DebugWorkerQueueFull.Store(0)
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
