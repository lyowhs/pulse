package wiresocket

// ring.go — lock-free MPSC (multiple-producer, single-consumer) event ring
// buffer for per-channel event delivery (Item 2 optimisation).
//
// Replaces the buffered Go channel (chan *Event) previously used as ch.events.
// The ring eliminates per-push mutex overhead and reduces goroutine wakeup
// latency for the common case where the consumer is already waiting.
//
// Design:
//   - wHead: uint64, monotonically increasing, claimed by producers via CAS.
//   - rHead: uint64, monotonically increasing, advanced by the single consumer.
//   - Slots: []atomic.Pointer[Event] indexed by (head & mask).
//   - sig:   chan struct{} (cap=1), signalled on every successful push to
//     wake a sleeping consumer without requiring a mutex.
//
// Overflow policy: drop-newest.  When the ring is full, push() returns false
// and the caller discards the new event.  For reliable channels, flow control
// (myWindow) prevents overflow in normal operation.  For unreliable channels,
// drop-newest is equivalent to the prior drop-oldest in terms of loss rate;
// the application should tolerate event loss on unreliable channels.

import (
	"runtime"
	"sync/atomic"
)

// eventRing is a fixed-capacity lock-free MPSC ring buffer.
// Capacity is always a power of 2 chosen at construction time.
type eventRing struct {
	buf  []atomic.Pointer[Event] // ring slots; len is a power of 2
	cap_ uint32                  // capacity (power of 2)
	mask uint32                  // cap_ - 1, for index masking

	wHead atomic.Uint64 // producers claim slots via CAS; advances monotonically
	_     [6]uint64     // pad wHead onto its own cache line (avoid false sharing with rHead)

	rHead atomic.Uint64 // consumer only; advances after each successful pop
	_     [7]uint64     // pad rHead onto its own cache line

	sig  chan struct{} // cap=1; signalled on each push to wake sleeping consumer
	done chan struct{} // closed by ring.close(); wakes consumer on shutdown
}

// newEventRing allocates an eventRing with at least minCap capacity.
// The actual capacity is rounded up to the next power of 2.
func newEventRing(minCap int) *eventRing {
	c := 1
	for c < minCap {
		c <<= 1
	}
	r := &eventRing{
		buf:  make([]atomic.Pointer[Event], c),
		cap_: uint32(c),
		mask: uint32(c - 1),
		sig:  make(chan struct{}, 1),
		done: make(chan struct{}),
	}
	return r
}

// push enqueues e into the ring.  Returns true on success, false if the ring
// is full (caller should discard e — drop-newest policy).
//
// Safe to call from multiple goroutines concurrently (MPSC producer side).
func (r *eventRing) push(e *Event) bool {
	for {
		wh := r.wHead.Load()
		rh := r.rHead.Load()
		if wh-rh >= uint64(r.cap_) {
			return false // full — drop newest
		}
		if r.wHead.CompareAndSwap(wh, wh+1) {
			// Slot claimed; store the event.
			r.buf[uint32(wh)&r.mask].Store(e)
			// Signal the consumer.  Non-blocking: if sig is already full
			// the consumer has already been notified and will drain all items.
			select {
			case r.sig <- struct{}{}:
			default:
			}
			return true
		}
		// CAS lost (another producer claimed this slot); retry.
	}
}

// pop removes and returns the oldest event from the ring.
// Returns (nil, false) if the ring is empty.
//
// Must be called from a single goroutine only (SPSC consumer side).
//
// Note: there is a very brief window between a producer's CAS on wHead and
// its subsequent Store into the slot.  In that window the slot contains nil
// even though wHead has advanced.  pop spins (yielding with Gosched) until
// the store completes.  This window is typically < 10 ns on modern hardware.
func (r *eventRing) pop() (*Event, bool) {
	rh := r.rHead.Load()
	if rh >= r.wHead.Load() {
		return nil, false // empty
	}
	// Spin until the producer's Store completes.
	slot := &r.buf[uint32(rh)&r.mask]
	var e *Event
	for {
		e = slot.Load()
		if e != nil {
			break
		}
		runtime.Gosched()
	}
	slot.Store(nil)               // clear for GC
	r.rHead.Store(rh + 1)        // advance consumer head
	return e, true
}

// Len returns the approximate number of items currently in the ring.
// May be stale by the time the caller reads it; safe for flow-control
// estimates but not for exact synchronisation.
func (r *eventRing) Len() int {
	wh := r.wHead.Load()
	rh := r.rHead.Load()
	if wh <= rh {
		return 0
	}
	n := int(wh - rh)
	if n > int(r.cap_) {
		return int(r.cap_)
	}
	return n
}

// Cap returns the ring's fixed capacity.
func (r *eventRing) Cap() int { return int(r.cap_) }

// Sig returns the signal channel (capacity 1).
// A receive on Sig() means at least one item is available; the consumer
// must call pop() in a loop to drain all ready items.
func (r *eventRing) Sig() <-chan struct{} { return r.sig }

// Done returns the done channel (closed by ring.close()).
func (r *eventRing) Done() <-chan struct{} { return r.done }

// close permanently closes the ring.  Any consumer blocked in a select on
// Sig() will be woken via a send to sig so it can observe the close.
func (r *eventRing) close() {
	// Synchronise the close using the atomic package to avoid a double-close
	// panic if close is called concurrently.  We use a CAS on a sentinel
	// value in wHead.  Actually, done is closed only once by Channel.closeLocal
	// via sync.Once, so a simple close is safe.
	close(r.done)
	select {
	case r.sig <- struct{}{}:
	default:
	}
}

// drainTo pops all pending events from the ring and calls f on each one.
// Used by closeLocal to discard buffered events on channel teardown.
func (r *eventRing) drainTo(f func(*Event)) {
	for {
		e, ok := r.pop()
		if !ok {
			return
		}
		f(e)
	}
}

// BenchmarkEventRingPush / Pop are in ring_internal_test.go.

// ── helpers used only in tests ──────────────────────────────────────────────

// mustPop is a test helper that calls pop() and panics if the ring is empty.
// Defined here (not in a test file) so internal-package tests can use it.
func (r *eventRing) mustPop() *Event {
	e, ok := r.pop()
	if !ok {
		panic("eventRing.mustPop: ring is empty")
	}
	return e
}

// ── atomic helpers ────────────────────────────────────────────────────────────

// loadUint32 is a convenience wrapper so callers need not cast.
func loadUint32(v *atomic.Uint64) uint32 { return uint32(v.Load()) }
