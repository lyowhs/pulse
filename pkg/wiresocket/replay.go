package wiresocket

import "sync"

// replayWindow is a 64-bit sliding window counter for detecting replayed
// or duplicate data packets, identical in design to WireGuard's.
//
// The window covers [head-windowSize+1, head].  Packets outside this range
// on the left are too old and rejected; packets in range but already seen
// are rejected.
type replayWindow struct {
	mu   sync.Mutex
	head uint64
	bits uint64 // bitmap: bit i set means (head-i) has been received
}

const windowSize = 64

// check returns true if counter should be accepted (not a replay / not too
// old).  It does NOT record the counter — call update after decryption
// succeeds.
func (rw *replayWindow) check(counter uint64) bool {
	rw.mu.Lock()
	defer rw.mu.Unlock()

	if counter > rw.head {
		return true // ahead of window — definitely fresh
	}
	diff := rw.head - counter
	if diff >= windowSize {
		return false // too old
	}
	return rw.bits&(1<<diff) == 0 // not yet seen
}

// update marks counter as received.  Must be called only after decryption
// succeeds and check returned true (or the caller is certain the counter is
// valid).
func (rw *replayWindow) update(counter uint64) {
	rw.mu.Lock()
	defer rw.mu.Unlock()

	if counter > rw.head {
		shift := counter - rw.head
		if shift >= windowSize {
			rw.bits = 0
		} else {
			rw.bits <<= shift
		}
		rw.head = counter
	}
	diff := rw.head - counter
	if diff < windowSize {
		rw.bits |= 1 << diff
	}
}
