package wiresocket

import (
	"sync"
	"sync/atomic"
)

// replayWindow is a sliding window counter for detecting replayed or duplicate
// data packets.
//
// The window covers [head-windowSize+1, head].  Packets outside this range on
// the left are too old and rejected; packets in range but already seen are
// rejected.
//
// The window is implemented as a [windowWords]uint64 bitmap where bit i
// (counting from 0 at the LSB of bits[0]) represents counter (head-i).
// windowSize = windowWords × 64 = 4096 entries.  The larger window (vs. the
// original 64) is necessary because sendFragments allocates all fragment
// counters in a tight loop before the batch is actually written to the socket:
// if a concurrent keepalive send steals a counter in the middle of that loop
// and the keepalive arrives at the peer before the fragment batch, the peer's
// head advances past the early fragment counters, causing spurious replay
// rejections.  A 4096-entry window accommodates up to ~11 concurrent 367-
// fragment events (inflightCap × fragsPerEvent for the default bench MTU) with
// plenty of headroom.
//
// head is stored atomically so that check() can take a lock-free fast-path
// for the common case of strictly in-order packet arrival.
type replayWindow struct {
	head atomic.Uint64         // current maximum counter seen
	mu   sync.Mutex
	bits [windowWords]uint64   // bits[w] bit b ↔ counter (head - w*64 - b) was received; protected by mu
}

const (
	windowWords = 64           // 64 words × 64 bits = 4096-entry window
	windowSize  = windowWords * 64
)

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
	head = rw.head.Load() // re-read under lock for a consistent view
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
	result := rw.bits[diff/64]&(1<<(diff%64)) == 0
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
		rw.shiftLeft(shift)
		rw.head.Store(counter)
		head = counter
	}
	diff := head - counter
	if diff < windowSize {
		rw.bits[diff/64] |= 1 << (diff % 64)
	}
	rw.mu.Unlock()
}

// shiftLeft slides the window forward by shift positions, zeroing the newly
// exposed low bits (which represent the fresh head slots not yet received).
// Must be called with mu held.
//
// Bit layout: bit i (word i/64, position i%64) represents counter (head-i).
// After advancing head by shift, old bit i → new bit i+shift.  The words are
// treated as a little-endian multi-word integer and shifted left by shift bits.
func (rw *replayWindow) shiftLeft(shift uint64) {
	if shift >= windowSize {
		for i := range rw.bits {
			rw.bits[i] = 0
		}
		return
	}
	ws := int(shift / 64) // whole-word shift
	bs := shift % 64      // bit shift within a word
	// Process from high word to low to avoid overwriting source data.
	for w := windowWords - 1; w >= 0; w-- {
		src := w - ws
		if src < 0 {
			rw.bits[w] = 0
		} else {
			rw.bits[w] = rw.bits[src] << bs
			if bs > 0 && src > 0 {
				rw.bits[w] |= rw.bits[src-1] >> (64 - bs)
			}
		}
	}
}
