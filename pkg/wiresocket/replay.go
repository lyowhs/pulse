package wiresocket

import (
	"sync"
	"sync/atomic"
)

// replayWindow is a 64-bit sliding window counter for detecting replayed
// or duplicate data packets, identical in design to WireGuard's.
//
// The window covers [head-windowSize+1, head].  Packets outside this range
// on the left are too old and rejected; packets in range but already seen
// are rejected.
//
// head is stored atomically so that check() can take a lock-free fast-path
// for the common case of strictly in-order packet arrival.
type replayWindow struct {
	head atomic.Uint64 // current maximum counter seen
	mu   sync.Mutex
	bits uint64 // bitmap: bit i set means (head-i) has been received; protected by mu
}

const windowSize = 64

// check returns true if counter should be accepted (not a replay / not too
// old).  It does NOT record the counter — call update after decryption
// succeeds.
//
// For in-order streams (the common case) the fast-path avoids acquiring mu.
func (rw *replayWindow) check(counter uint64) bool {
	head := rw.head.Load()
	if counter > head {
		return true // fast path — definitely fresh, no lock needed
	}
	diff := head - counter
	if diff >= windowSize {
		dbg("replay: counter too old", "counter", counter, "head", head, "age", diff)
		return false // fast path — definitely too old, no lock needed
	}

	// Slow path: must check the bitmap under the lock because head may advance
	// between the Load above and the bitmap read, and update() mutates both
	// under the same lock.
	rw.mu.Lock()
	head = rw.head.Load() // re-read under lock to get a consistent view
	if counter > head {
		rw.mu.Unlock()
		return true
	}
	diff = head - counter
	if diff >= windowSize {
		dbg("replay: counter too old", "counter", counter, "head", head, "age", diff)
		rw.mu.Unlock()
		return false
	}
	result := rw.bits&(1<<diff) == 0
	if !result {
		dbg("replay: duplicate counter", "counter", counter, "head", head)
	}
	rw.mu.Unlock()
	return result
}

// update marks counter as received.  Must be called only after decryption
// succeeds and check returned true (or the caller is certain the counter is
// valid).
func (rw *replayWindow) update(counter uint64) {
	rw.mu.Lock()
	head := rw.head.Load()
	if counter > head {
		shift := counter - head
		if shift >= windowSize {
			rw.bits = 0
		} else {
			rw.bits <<= shift
		}
		rw.head.Store(counter)
	}
	diff := rw.head.Load() - counter
	if diff < windowSize {
		rw.bits |= 1 << diff
	}
	rw.mu.Unlock()
}
