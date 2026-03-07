package wiresocket

// sendq_internal_test.go — unit tests and benchmarks for the async send
// queue and flushLoop goroutine (Item 1 optimisation).

import (
	"sync"
	"testing"
	"time"
)

// ── Correctness ───────────────────────────────────────────────────────────────

// TestSendQueueConstants verifies that sendQueueCapFor produces values that
// satisfy the core ordering invariant: sendQueueCapFor(n) > n for all n, so
// that a full window burst can be enqueued without triggering the synchronous
// fallback that would reorder frames.
func TestSendQueueConstants(t *testing.T) {
	t.Parallel()
	// sendQueueBatch must be a reasonable positive constant.
	if sendQueueBatch < 1 {
		t.Errorf("sendQueueBatch=%d, want >= 1", sendQueueBatch)
	}

	// sendQueueCapFor(n) must strictly exceed n so that enqueueing a full
	// window burst (n frames) plus a few concurrent ACK/retransmit frames
	// does not overflow.  This is the invariant that prevents the sync
	// fallback from reordering frames relative to queued window-burst frames.
	for _, n := range []int{1, 48, 64, 256, 512, 1024, 2137, 2048, 4096, 8000} {
		cap := sendQueueCapFor(n)
		if cap <= n {
			t.Errorf("sendQueueCapFor(%d) = %d, want > %d (must exceed inflightCap)", n, cap, n)
		}
		// Result must be a power of two.
		if cap&(cap-1) != 0 {
			t.Errorf("sendQueueCapFor(%d) = %d, not a power of two", n, cap)
		}
		// Result must be >= sendQueueBatch (queue must be useful even when
		// eventBufSize is very small).
		if cap < sendQueueBatch {
			t.Errorf("sendQueueCapFor(%d) = %d, want >= sendQueueBatch=%d", n, cap, sendQueueBatch)
		}
	}
}

// TestSendQueueItemDrainQ verifies drainSendQ returns pool buffers without
// leaking: after enqueuing N items and draining them, the queue is empty.
func TestSendQueueDrainQ(t *testing.T) {
	t.Parallel()

	s := &session{
		sendQ: make(chan sendQueueItem, sendQueueCapFor(256)),
	}

	// Enqueue a few items with real pool buffers.
	const n = 3
	for i := 0; i < n; i++ {
		bp := getSendBuf(128)
		s.sendQ <- sendQueueItem{pkt: (*bp)[:4], bp: bp}
	}

	if len(s.sendQ) != n {
		t.Fatalf("expected %d items in sendQ before drain, got %d", n, len(s.sendQ))
	}

	s.drainSendQ()

	if len(s.sendQ) != 0 {
		t.Errorf("sendQ not empty after drainSendQ: %d items remain", len(s.sendQ))
	}
}

// TestSendQBlocksWhenFull verifies that when the sendQ channel is full a
// producer goroutine blocks (not bypasses with a synchronous write).  The
// old sync-fallback path caused out-of-order delivery because sync-sent
// frames bypassed queued frames, creating OOO gaps that overwhelmed the
// 64-bit SACK bitmap and triggered retransmit storms.
func TestSendQBlocksWhenFull(t *testing.T) {
	t.Parallel()

	const cap = 4
	q := make(chan sendQueueItem, cap)
	done := make(chan struct{})

	// Fill the queue to capacity.
	for i := 0; i < cap; i++ {
		bp := getSendBuf(4)
		*bp = (*bp)[:1] // reslice to length 1 (pool returns len=0, cap>=4)
		(*bp)[0] = byte(i)
		q <- sendQueueItem{pkt: *bp, bp: bp}
	}

	// Try to enqueue one more item: this must block, not fall through.
	blocked := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		close(blocked) // signal that we're about to block
		select {
		case q <- sendQueueItem{}:
		case <-done:
		}
	}()

	// Wait until the goroutine has entered the select.
	<-blocked
	// Give it a moment to confirm it is actually blocked (not racing past).
	time.Sleep(5 * time.Millisecond)

	// Verify the queue is still full (goroutine is blocked, not skipped).
	if n := len(q); n != cap {
		t.Errorf("expected sendQ len=%d while full, got %d (goroutine bypassed the queue)", cap, n)
	}

	// Drain one slot; the blocked goroutine should now unblock.
	item := <-q
	putSendBuf(item.bp)

	wg.Wait()
}

// TestSendQUnblocksOnSessionClose verifies that a goroutine blocked waiting
// for sendQ space is released when the session's done channel is closed.
// This is the ErrConnClosed path in session.send().
func TestSendQUnblocksOnSessionClose(t *testing.T) {
	t.Parallel()

	const cap = 2
	q := make(chan sendQueueItem, cap)
	done := make(chan struct{})

	// Fill the queue so the next put will block.
	for i := 0; i < cap; i++ {
		q <- sendQueueItem{}
	}

	unblocked := make(chan bool, 1)
	go func() {
		select {
		case q <- sendQueueItem{}:
			unblocked <- false // unexpected: queued instead of cancelled
		case <-done:
			unblocked <- true // expected path
		}
	}()

	// Close the session done channel; the goroutine must exit via <-done.
	time.Sleep(2 * time.Millisecond)
	close(done)

	select {
	case viaDone := <-unblocked:
		if !viaDone {
			t.Error("goroutine exited via queue put, not via done channel")
		}
	case <-time.After(time.Second):
		t.Fatal("goroutine did not unblock after done was closed")
	}
}

// TestSendQFIFOOrder verifies that items enqueued to sendQ are delivered in
// FIFO order.  This is the invariant that prevents OOO frame delivery; a
// synchronous bypass would break it by inserting items out of sequence.
func TestSendQFIFOOrder(t *testing.T) {
	t.Parallel()

	const n = 8
	q := make(chan sendQueueItem, n)

	// Enqueue items tagged with their send order via the first payload byte.
	for i := 0; i < n; i++ {
		bp := getSendBuf(4)
		*bp = (*bp)[:1] // reslice to length 1 (pool returns len=0, cap>=4)
		(*bp)[0] = byte(i)
		q <- sendQueueItem{pkt: *bp, bp: bp}
	}

	// Dequeue and verify FIFO order.
	for i := 0; i < n; i++ {
		item := <-q
		if got := item.pkt[0]; got != byte(i) {
			t.Errorf("position %d: got order tag %d, want %d (FIFO violated)", i, got, i)
		}
		putSendBuf(item.bp)
	}
}

// ── Benchmarks ────────────────────────────────────────────────────────────────

// BenchmarkSendQEnqueue measures the cost of enqueuing one item into a
// buffered channel (the async path in session.send before flushLoop drains).
func BenchmarkSendQEnqueue(b *testing.B) {
	q := make(chan sendQueueItem, sendQueueCapFor(defaultReliableWindow))
	bp := getSendBuf(128)
	item := sendQueueItem{pkt: (*bp)[:4], bp: bp}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		select {
		case q <- item:
		default:
		}
		// Drain immediately so the queue doesn't fill.
		select {
		case <-q:
		default:
		}
	}
}
