package wiresocket

// sendq.go — async send queue with batched sendmmsg (Item 1 optimisation).
//
// session.send() encrypts a packet and enqueues it to sendQ instead of
// calling writeRetry directly.  A single per-session flushLoop goroutine
// drains the queue and calls WriteBatch (sendmmsg on Linux), amortising the
// per-syscall overhead across up to sendQueueBatch packets.
//
// For fragmented frames, sendFragments already builds a batch and calls
// writeBatchMsgs itself; those frames bypass the queue.
//
// On a loopback/GbE path:
//   - Before: ~1500 ns/packet (one sendto syscall per send)
//   - After:  ~23 ns/packet amortised (64 packets per sendmmsg)

import (
	"errors"
	"runtime"
	"syscall"

	"golang.org/x/net/ipv4"
)

const (
	// sendQueueBatch is the maximum number of packets flushed in a single
	// WriteBatch (sendmmsg) call.
	sendQueueBatch = 64
)

// sendQueueCapFor returns the sendQ channel capacity for a session whose
// receive-side event buffer holds eventBufSize events (the inflightCap).
//
// The capacity must exceed eventBufSize so that a full window burst (up to
// eventBufSize frames, one per event in the worst case) plus a small number
// of concurrent ACK / retransmit frames can all be enqueued without hitting
// the synchronous fallback in session.send.  The synchronous fallback bypasses
// the FIFO queue and reorders frames relative to queued frames, which breaks
// the receiver's reliable-delivery invariants.
//
// nextPow2(eventBufSize + sendQueueBatch) gives the next power of two above
// eventBufSize for non-power-of-two inflightCap values (e.g. 2137 → 4096) and
// provides a sendQueueBatch-sized headroom margin for concurrent sends at every
// other inflightCap value.
func sendQueueCapFor(eventBufSize int) int {
	n := eventBufSize + sendQueueBatch
	if n < sendQueueBatch {
		n = sendQueueBatch
	}
	return nextPow2(n)
}

// nextPow2 returns the smallest power of two that is >= n.  Returns 1 for n <= 1.
func nextPow2(n int) int {
	if n <= 1 {
		return 1
	}
	p := 1
	for p < n {
		p <<= 1
	}
	return p
}

// sendQueueItem is one encrypted packet ready to be written to the wire.
type sendQueueItem struct {
	pkt []byte   // encrypted packet (sub-slice of pool buffer)
	bp  *[]byte  // pool buffer handle; returned by flushLoop after send
}

// flushLoop drains sendQ in batches and writes them via WriteBatch.
// It runs as a dedicated goroutine for the lifetime of the session.
//
// On session close (s.done closed), flushLoop sends all remaining queued
// packets before exiting so that data enqueued immediately before Close()
// (e.g. by the coalescer's stop flush) is not silently discarded.
func (s *session) flushLoop() {
	// Pre-allocate batch state once; reused across iterations.
	items := make([]sendQueueItem, 0, sendQueueBatch)
	// bufs holds raw packet slices so msgs[i].Buffers can be a sub-slice
	// of bufs without a per-message [][]byte allocation.
	bufs := make([][]byte, sendQueueBatch)
	msgs := make([]ipv4.Message, sendQueueBatch)

	for {
		// Block until a packet arrives or the session closes.
		select {
		case <-s.done:
			// Session closed: flush any packets already queued, then exit.
			// This is critical for coalescer.stop() which enqueues to sendQ
			// and only then calls sess.close() — if we discarded here, the
			// last batch of data frames would never reach the peer.
			s.flushAndDrainSendQ(items[:0], bufs, msgs)
			return
		case item := <-s.sendQ:
			items = append(items[:0], item)
		}

		// Non-blocking drain: collect up to sendQueueBatch packets.
	drainMore:
		for len(items) < sendQueueBatch {
			select {
			case item := <-s.sendQ:
				items = append(items, item)
			default:
				break drainMore
			}
		}

		if err := s.sendBatch(items, bufs, msgs); err != nil {
			dbg("flushLoop: write error, closing session",
				"local_index", s.localIndex,
				"err",         err,
			)
			DebugFlushLoopErrors.Add(1)
			s.close()
			s.drainSendQ()
			return
		}
	}
}

// flushAndDrainSendQ sends all remaining items in sendQ (non-blocking
// drain after session close), then returns pool buffers for any that fail.
func (s *session) flushAndDrainSendQ(items []sendQueueItem, bufs [][]byte, msgs []ipv4.Message) {
	for {
		// Non-blocking: collect whatever is left.
		items = items[:0]
	drainMore:
		for len(items) < sendQueueBatch {
			select {
			case item := <-s.sendQ:
				items = append(items, item)
			default:
				break drainMore
			}
		}
		if len(items) == 0 {
			return
		}
		// Best-effort send; ignore errors (session already closed).
		_ = s.sendBatch(items, bufs, msgs)
	}
}

// sendBatch builds msgs from items, calls writeBatchMsgs, returns pool
// buffers, and updates lastSend on success.  Returns any write error.
func (s *session) sendBatch(items []sendQueueItem, bufs [][]byte, msgs []ipv4.Message) error {
	n := len(items)
	for i, it := range items {
		bufs[i] = it.pkt
	}
	msgs = msgs[:n]
	for i := 0; i < n; i++ {
		msgs[i] = ipv4.Message{Buffers: bufs[i : i+1 : i+1], Addr: s.remoteAddr}
	}

	dbg("flushLoop: sending batch",
		"local_index", s.localIndex,
		"batch_size",  n,
	)

	err := s.writeBatchMsgs(msgs)

	// Always return pool buffers.
	for _, it := range items {
		putSendBuf(it.bp)
	}
	if err == nil {
		s.touchLastSend()
	}
	return err
}

// drainSendQ discards all pending items and returns their pool buffers.
// Called after a write error when the session is already closed.
func (s *session) drainSendQ() {
	for {
		select {
		case item := <-s.sendQ:
			putSendBuf(item.bp)
		default:
			return
		}
	}
}

// writeBatchMsgs sends msgs via WriteBatch (sendmmsg on Linux) or falls back
// to a writeRetry loop on platforms where sendmmsg is unavailable.
// It retries automatically on ENOBUFS (macOS send-buffer exhaustion).
//
// This helper is shared by flushLoop (batched single-packet sends) and
// sendFragments (batched multi-fragment large frames).
func (s *session) writeBatchMsgs(msgs []ipv4.Message) error {
	switch {
	case s.pc != nil:
		sent := 0
		for sent < len(msgs) {
			n, err := s.pc.WriteBatch(msgs[sent:], 0)
			sent += n
			if err != nil {
				if errors.Is(err, syscall.ENOBUFS) ||
					errors.Is(err, syscall.EAGAIN) ||
					errors.Is(err, syscall.EWOULDBLOCK) {
					dbg("writeBatchMsgs: ENOBUFS/EAGAIN, retrying",
						"local_index", s.localIndex,
						"sent",        sent,
						"total",       len(msgs),
					)
					runtime.Gosched()
					continue
				}
				if errors.Is(err, syscall.EINTR) {
					// Transient signal interrupt (e.g. Go async preemption via
					// SIGURG) — retry from where we left off.  sent already
					// reflects any messages sent before the interrupt.
					continue
				}
				return err
			}
		}
	case s.pc6 != nil:
		sent := 0
		for sent < len(msgs) {
			n, err := s.pc6.WriteBatch(msgs[sent:], 0)
			sent += n
			if err != nil {
				if errors.Is(err, syscall.ENOBUFS) ||
					errors.Is(err, syscall.EAGAIN) ||
					errors.Is(err, syscall.EWOULDBLOCK) {
					dbg("writeBatchMsgs: ENOBUFS/EAGAIN on IPv6, retrying",
						"local_index", s.localIndex,
						"sent",        sent,
						"total",       len(msgs),
					)
					runtime.Gosched()
					continue
				}
				if errors.Is(err, syscall.EINTR) {
					continue
				}
				return err
			}
		}
	default:
		// No WriteBatch support: plain per-packet loop with ENOBUFS retry.
		for _, msg := range msgs {
			if err := s.writeRetry(msg.Buffers[0]); err != nil {
				return err
			}
		}
	}
	return nil
}
