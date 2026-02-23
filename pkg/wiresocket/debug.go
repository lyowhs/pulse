package wiresocket

import (
	"log/slog"
	"sync/atomic"
)

// debugLog holds the package-level debug logger. nil means disabled (default).
var debugLog atomic.Pointer[slog.Logger]

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
