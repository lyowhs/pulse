package wiresocket

import "sync"

// Three size-classed pools for outgoing (send) and incoming (recv) buffers.
//
// The previous single 65 KB pool caused cache pollution: a 128-byte payload
// borrowed a 65 KB buffer, evicting ~1000 live cache lines on every send or
// receive.  Routing frames to the smallest pool that fits keeps the hot working
// set in L1/L2 cache and improves throughput for small-payload workloads.
//
// Size classes:
//   ≤ poolSmallCap (2 KB)  — small payloads; MTU ≤ 1472 single-fragment frames
//   ≤ poolMedCap   (16 KB) — medium frames up to ~15 KB
//   > poolMedCap           — jumbo / max-size frames (original 65 KB behaviour)
const (
	poolSmallCap = 2048
	poolMedCap   = 16384
)

var (
	// Send-side pools: capacity must cover header + plaintext + AEAD tag.
	smallSendPool = &sync.Pool{New: func() any { b := make([]byte, 0, poolSmallCap); return &b }}
	medSendPool   = &sync.Pool{New: func() any { b := make([]byte, 0, poolMedCap); return &b }}
	largeSendPool = &sync.Pool{New: func() any { b := make([]byte, 0, 65535+sizeAEADTag); return &b }}

	// Recv-side pools: capacity for AEAD plaintext output (no tag overhead).
	smallRecvPool = &sync.Pool{New: func() any { b := make([]byte, 0, poolSmallCap); return &b }}
	medRecvPool   = &sync.Pool{New: func() any { b := make([]byte, 0, poolMedCap); return &b }}
	largeRecvPool = &sync.Pool{New: func() any { b := make([]byte, 0, 65535); return &b }}
)

// getSendBuf returns a pooled send buffer guaranteed to hold at least needed
// bytes.  The buffer must be returned with putSendBuf.
func getSendBuf(needed int) *[]byte {
	switch {
	case needed <= poolSmallCap:
		return smallSendPool.Get().(*[]byte)
	case needed <= poolMedCap:
		return medSendPool.Get().(*[]byte)
	default:
		return largeSendPool.Get().(*[]byte)
	}
}

// putSendBuf returns bp to the appropriate size-class send pool.
// Routes by cap(*bp) so that buffers that were reallocated to a larger size
// (e.g. by AppendMarshal) land in the correct pool.
func putSendBuf(bp *[]byte) {
	switch {
	case cap(*bp) <= poolSmallCap:
		smallSendPool.Put(bp)
	case cap(*bp) <= poolMedCap:
		medSendPool.Put(bp)
	default:
		largeSendPool.Put(bp)
	}
}

// getRecvBuf returns a pooled receive buffer with capacity for at least needed
// plaintext bytes.  The buffer must be returned with putRecvBuf.
func getRecvBuf(needed int) *[]byte {
	switch {
	case needed <= poolSmallCap:
		return smallRecvPool.Get().(*[]byte)
	case needed <= poolMedCap:
		return medRecvPool.Get().(*[]byte)
	default:
		return largeRecvPool.Get().(*[]byte)
	}
}

// putRecvBuf returns bp to the appropriate size-class receive pool.
func putRecvBuf(bp *[]byte) {
	switch {
	case cap(*bp) <= poolSmallCap:
		smallRecvPool.Put(bp)
	case cap(*bp) <= poolMedCap:
		medRecvPool.Put(bp)
	default:
		largeRecvPool.Put(bp)
	}
}

// ── Frame pools (Item 5) ───────────────────────────────────────────────────────

// ackFramePool recycles Frame objects for ACK-only outgoing frames (Events == nil).
// These frames are sent immediately and never stored in pending, so they are
// safe to return to the pool as soon as sess.send() returns.
var ackFramePool = sync.Pool{New: func() any { return &Frame{} }}

// singleEventFrame bundles a Frame with a fixed 1-element Events backing array,
// eliminating the two separate heap allocations that Frame{Events:[]*Event{e}}
// would otherwise require (one for the Frame struct, one for the slice backing).
//
// Used by Channel.Send on the direct (non-coalesced) path.  For reliable channels
// the singleEventFrame is held in pendingFrame.poolSF and returned to the pool
// when the ACK arrives; for unreliable channels it is returned immediately after
// sess.send() returns.
type singleEventFrame struct {
	f    Frame
	slot [1]*Event // backing array; f.Events points here via slot[:1:1]
}

// singleEventFramePool recycles singleEventFrame objects.
var singleEventFramePool = sync.Pool{New: func() any { return &singleEventFrame{} }}

// getSingleEventFrame borrows a singleEventFrame from the pool and initialises
// it with chId and e.  The caller must return it with putSingleEventFrame (unreliable
// path) or via pendingFrame.poolSF → onAck/reset (reliable path).
//
// All Frame fields are re-initialised here, after pool.Get's happens-before
// barrier.  putSingleEventFrame only clears slot[0] (for GC) and skips the
// Frame zero, so there is no write to sf.f inside putSingleEventFrame that
// could race with a concurrent retransmit goroutine reading sf.f from its
// captured frame pointer.
func getSingleEventFrame(chId uint16, e *Event) *singleEventFrame {
	sf := singleEventFramePool.Get().(*singleEventFrame)
	sf.slot[0] = e
	sf.f = Frame{ChannelId: chId, Events: sf.slot[:1:1]}
	return sf
}

// putSingleEventFrame clears sf and returns it to the pool.
// Only the event reference is cleared for GC; Frame fields are re-initialised
// by getSingleEventFrame after the next pool.Get.
func putSingleEventFrame(sf *singleEventFrame) {
	sf.slot[0] = nil // release the Event reference for GC
	singleEventFramePool.Put(sf)
}
