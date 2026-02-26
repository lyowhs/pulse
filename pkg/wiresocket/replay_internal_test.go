package wiresocket

import (
	"sync"
	"testing"
)

// ─── replayWindow white-box unit tests ────────────────────────────────────────
// These tests live in package wiresocket (not wiresocket_test) so they can
// access the unexported replayWindow type and its constants directly.

// TestReplayWindowFresh verifies that a counter strictly greater than the
// current head is accepted and that head advances after update.
func TestReplayWindowFresh(t *testing.T) {
	var rw replayWindow

	if !rw.check(1) {
		t.Error("check(1) with empty window: want accepted")
	}
	rw.update(1)
	if h := rw.head.Load(); h != 1 {
		t.Errorf("head after update(1): got %d, want 1", h)
	}
	// A counter ahead of head is always fresh.
	if !rw.check(100) {
		t.Error("check(100) with head=1: want accepted (counter > head)")
	}
}

// TestReplayWindowDuplicate verifies that a counter that has already been
// recorded is rejected on the second check.
func TestReplayWindowDuplicate(t *testing.T) {
	var rw replayWindow
	rw.update(5)
	if rw.check(5) {
		t.Error("check(5) after update(5): want rejected (duplicate)")
	}
}

// TestReplayWindowTooOld verifies that a counter more than windowSize positions
// behind the head is rejected without consulting the bitmap.
func TestReplayWindowTooOld(t *testing.T) {
	var rw replayWindow
	rw.update(uint64(windowSize) + 1)
	if rw.check(1) {
		t.Error("check(1) with head=windowSize+1: want rejected (too old)")
	}
}

// TestReplayWindowBoundary checks the edge case where diff == windowSize-1
// (last valid slot, must be accepted) and diff == windowSize (first invalid
// slot, must be rejected).
func TestReplayWindowBoundary(t *testing.T) {
	var rw replayWindow
	head := uint64(windowSize) + 5
	rw.update(head)

	// diff = windowSize - 1 → still inside window → accepted.
	innerCounter := head - uint64(windowSize) + 1
	if !rw.check(innerCounter) {
		t.Errorf("check(%d): want accepted (diff=windowSize-1)", innerCounter)
	}

	// diff = windowSize → exactly at boundary → rejected (too old).
	outerCounter := head - uint64(windowSize)
	if rw.check(outerCounter) {
		t.Errorf("check(%d): want rejected (diff=windowSize)", outerCounter)
	}
}

// TestReplayWindowInWindow verifies that an unseen counter within the window
// is accepted, and a previously updated one within the window is rejected.
func TestReplayWindowInWindow(t *testing.T) {
	var rw replayWindow
	rw.update(100) // head = 100

	// Counter 80 is within the window and not yet seen → accepted.
	if !rw.check(80) {
		t.Error("check(80) with head=100: want accepted (unseen, in window)")
	}
	rw.update(80)
	// Now counter 80 is seen → rejected.
	if rw.check(80) {
		t.Error("check(80) after update(80): want rejected (duplicate)")
	}
}

// TestReplayWindowLargeAdvance verifies that advancing head by more than
// windowSize clears all prior bitmap state so old counters are rejected.
func TestReplayWindowLargeAdvance(t *testing.T) {
	var rw replayWindow
	rw.update(1)
	rw.update(3)
	rw.update(5)

	// Advance past the entire window.
	bigHead := uint64(windowSize)*2 + 100
	rw.update(bigHead)

	for _, c := range []uint64{1, 3, 5} {
		if rw.check(c) {
			t.Errorf("check(%d) after large advance: want rejected (too old)", c)
		}
	}
}

// TestReplayWindowMultiWordShift verifies that a shift spanning multiple
// 64-bit words correctly preserves received-bit state across word boundaries.
func TestReplayWindowMultiWordShift(t *testing.T) {
	var rw replayWindow

	// Mark counters spread across the first few 64-bit words.
	for _, c := range []uint64{1, 65, 129} { // one per word
		rw.update(c)
	}
	// Advance by exactly 128 (two full words).
	rw.update(129 + 128)

	// Counter 129: diff from new head = 128, still inside window.
	// Was previously updated → must be seen (rejected).
	if rw.check(129) {
		t.Error("check(129) after shift by 128: want rejected (previously received)")
	}
	// Counter 1: diff from new head = 256, still inside the 4096-entry window.
	// Was previously updated → must be seen (rejected).
	if rw.check(1) {
		t.Error("check(1) after shift by 128: want rejected (previously received)")
	}
}

// TestReplayWindowAcceptAfterShift verifies that a freshly exposed slot (not
// previously received) remains accepted after a shift.
func TestReplayWindowAcceptAfterShift(t *testing.T) {
	var rw replayWindow
	rw.update(10)      // set head = 10
	rw.update(10 + 64) // advance by exactly one word; head = 74

	// Counter 5 is now at diff=69, within window, was never set → accepted.
	if !rw.check(5) {
		t.Error("check(5) after shift: want accepted (never received, within window)")
	}
}

// TestReplayWindowConcurrent exercises check and update from many goroutines
// simultaneously.  Its primary value is as a race-detector target.
func TestReplayWindowConcurrent(t *testing.T) {
	var rw replayWindow
	const goroutines = 8
	const perGoroutine = 500

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		base := uint64(g*perGoroutine) + 1
		go func(base uint64) {
			defer wg.Done()
			for i := uint64(0); i < perGoroutine; i++ {
				n := base + i
				if rw.check(n) {
					rw.update(n)
				}
			}
		}(base)
	}
	wg.Wait()

	// Each goroutine covers a disjoint range, so all counters should have
	// been accepted once.  head must lie within [1, goroutines*perGoroutine].
	maxCounter := uint64(goroutines * perGoroutine)
	if h := rw.head.Load(); h < 1 || h > maxCounter {
		t.Errorf("head = %d after concurrent updates, want in [1, %d]", h, maxCounter)
	}
}
