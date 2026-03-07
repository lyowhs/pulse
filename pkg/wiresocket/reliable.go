package wiresocket

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// defaultReliableWindow is the default reliable send/receive window in
	// events (not frames).  Because one coalesced frame may carry many events,
	// sizing the window in events rather than frames prevents the sender from
	// overflowing the receiver's channel buffer with a burst of large frames.
	// 4096 events supports high-throughput coalesced workloads without tuning.
	defaultReliableWindow = 4096
	defaultBaseRTO        = 200 * time.Millisecond
	defaultMaxRetries     = 10
	defaultACKDelay       = 20 * time.Millisecond
	maxRTO                = 30 * time.Second

	// reliableOOOWindow is the size of the out-of-order frame buffer.  It must
	// be at least as large as defaultReliableWindow so that a full in-flight
	// window of frames can arrive out-of-order without any being dropped.
	// Since defaultReliableWindow is now measured in events and each frame
	// carries at least one event, the worst-case in-flight frame count equals
	// defaultReliableWindow (one event per frame).  Both constants share the
	// same value so the invariant is always satisfied.
	reliableOOOWindow = defaultReliableWindow

	// sackBitmapBits is the width of the SACK bitmap in ACK frames.  The wire
	// format uses a uint64, so only the first 64 OOO slots can be selectively
	// acknowledged.  Frames in OOO slots 65..reliableOOOWindow are buffered
	// correctly but are not reported in SACK; the sender learns about them via
	// the cumulative ACK once the window advances past those positions.
	sackBitmapBits = 64
)

// ReliableCfg configures reliable delivery and flow control for a Channel.
// All fields are optional; zero values use the listed defaults.
type ReliableCfg struct {
	// WindowSize is the maximum number of unACKed frames allowed in-flight.
	// The sender blocks when this limit is reached until the receiver ACKs
	// frames and advances the window.  Default: 256.
	WindowSize int

	// BaseRTO is the initial retransmit timeout.  It doubles on each
	// consecutive retransmit attempt up to 30 s.  Default: 200 ms.
	BaseRTO time.Duration

	// MaxRetries is the number of retransmit attempts before the channel is
	// closed.  Default: 10.
	MaxRetries int

	// ACKDelay is the maximum time the receiver waits before sending a
	// standalone ACK.  ACKs are piggybacked on outgoing data frames when
	// possible and sent immediately; this delay applies only when the
	// channel has no data to send.  Default: 20 ms.
	ACKDelay time.Duration

	// MinFrameCost is the minimum number of window slots consumed by a
	// single preSend call (one coalesced frame).  When non-zero, each frame
	// costs max(len(frame.Events), MinFrameCost) window slots instead of
	// just len(frame.Events).
	//
	// This prevents frames with few events (e.g. 1-event frames from a
	// low-rate sender with a 100 µs coalesce interval) from consuming less
	// window budget than a full UDP packet's worth.  Without this cap, the
	// sender can have WindowSize × (1-event frames) in-flight simultaneously
	// — WindowSize UDP packets — which overflows the OS socket buffer when
	// WindowSize >> ic (the socket-buffer-derived frame cap).
	//
	// For auto-sized connections (EventBufSize = ic × eventsPerPacket), set
	// MinFrameCost = eventsPerPacket.  This ensures at most ic frames are
	// ever in-flight regardless of coalescing efficiency.
	//
	// 0 means no minimum (each frame costs max(len(Events), 1) slots).
	MinFrameCost int
}

func (c *ReliableCfg) withDefaults() ReliableCfg {
	out := *c
	if out.WindowSize <= 0 {
		out.WindowSize = defaultReliableWindow
	}
	if out.BaseRTO == 0 {
		out.BaseRTO = defaultBaseRTO
	}
	if out.MaxRetries == 0 {
		out.MaxRetries = defaultMaxRetries
	}
	if out.ACKDelay == 0 {
		out.ACKDelay = defaultACKDelay
	}
	return out
}

// pendingFrame is one slot in the send-side ring buffer.
type pendingFrame struct {
	seq      uint32
	frame    *Frame    // immutable once stored; re-sent as-is on retransmit
	poolSF   *singleEventFrame // non-nil: return to singleEventFramePool on ACK/reset
	sentAt   time.Time
	retries  int
	used     bool
	evtCount int // number of events in frame; used to decrement numPending by events
}

// reliableState is the per-channel reliability and flow-control state.
// It is attached to Channel.reliable; nil means unreliable (zero overhead).
type reliableState struct {
	cfg     ReliableCfg
	channel *Channel // back-reference for sending ACKs and closing channel

	// ── send side ─────────────────────────────────────────────────────────
	sendMu     sync.Mutex
	nextSeq uint32 // next sequence number to assign (starts at 1)
	// numPendingFast is a lock-free copy of numPending for the Nagle check in
	// the coalescer: when 0, all sent frames have been ACKed and the coalescer
	// can flush immediately instead of waiting for the timer.
	// Updated under sendMu; read lock-free (atomic) by the coalescer goroutine.
	numPendingFast atomic.Int32
	// oldestSeq is the lower-bound sequence number of the oldest in-flight
	// frame.  Updated to ackSeq on every cumulative ACK so that the ring-walk
	// in onAck and earliestPendingLocked covers only [oldestSeq, ackSeq) —
	// O(freed frames) — rather than the full ring — O(cfg.WindowSize).
	oldestSeq  uint32
	pending    []pendingFrame // ring buffer; len == cfg.WindowSize; indexed by seq % len
	numPending int            // total events (not frames) currently in-flight
	peerWindow int           // receiver-advertised window in events; starts at cfg.WindowSize
	cond       *sync.Cond     // wait when numPending >= peerWindow
	rtoRunning        bool          // true while rtoTimer is armed or retransmit is in-flight
	rto               time.Duration // current RTO (doubles on retransmit)
	rtoTimer          *time.Timer
	rtoEpoch          uint64        // incremented on every timer arm; stale goroutines self-abort
	retransmitInFlight bool         // true while retransmit() goroutine is blocked in sess.send()

	// probeRunning / probeEpoch implement the zero-window-probe mechanism.
	// When preSend() is about to block (flow-control wait), it arms a probe
	// timer that sends the oldest in-flight frame WITHOUT incrementing
	// p.retries.  The probe forces the receiver to set ackDirty=true and reply
	// with a fresh ACK, breaking the ackDirty=false deadlock that occurs when
	// the remote ackBatcher has already sent a full-window ACK and then goes
	// silent because no new frames arrive (preSend blocked → no new frames →
	// ackDirty stays false → no ACK → preSend blocked forever).
	// Protected by sendMu.
	probeRunning bool
	probeEpoch   uint64

	// retransmits counts the total number of frame retransmit events since
	// this reliableState was created or last reset.
	retransmits atomic.Int64

	// ── receive side ──────────────────────────────────────────────────────
	recvMu    sync.Mutex
	expectSeq uint32        // next in-order seq expected (starts at 1)
	ooo       uint64        // SACK bitmap: bit i = received seq expectSeq+i+1
	oooFrames [reliableOOOWindow]*Frame
	// oooHead is the circular-buffer head index into oooFrames.
	// The frame for (expectSeq+gap) is stored at slot
	//   (oooHead + gap - 1) % reliableOOOWindow
	// Advancing one in-order step increments oooHead by 1 (mod N) — O(1)
	// vs the previous O(N) memmove that shift-left required.
	oooHead int
	// ackDirty is set when the receiver has data to ACK back to the peer.
	// It is an atomic.Bool so that preSend can fast-path check it without
	// acquiring recvMu (item 7 optimization).  All writes still happen under
	// recvMu; reads outside recvMu use Load() only for the fast-path check.
	ackDirty atomic.Bool

	// windowWatchActive is true while the window-watch timer is running.
	// When we advertise window=0 (receiver buffer full), we start polling
	// every millisecond until the application drains events and myWindow()
	// becomes positive, at which point we immediately send a window update.
	// This prevents the sender from waiting a full ACKDelay (20ms) per event
	// when the receive buffer was momentarily full.
	// Protected by recvMu.
	windowWatchActive bool

	// lastAdvWindow is the window size we most recently advertised to the peer,
	// either via a standalone ACK or piggybacked on a data frame.
	// Initialised to cfg.WindowSize so that notifyWindowIncreased is a no-op
	// until we actually advertise a restricted window.
	// Protected by recvMu.
	lastAdvWindow uint32

	// lastWindowAckSeq is the AckSeq value of the most recent ACK from which
	// we updated peerWindow.  Because multiple goroutines can call sess.send()
	// concurrently (notifyWindowIncreased, windowWatch, preSend piggyback), ACK
	// packets carrying different window values but the same AckSeq can be
	// reordered by the kernel.  We apply TCP-style window update rules:
	//   - ackSeq > lastWindowAckSeq : new receiver state, apply peerWindow = w
	//   - ackSeq == lastWindowAckSeq: same state, take max(peerWindow, w)
	//   - ackSeq < lastWindowAckSeq : stale packet, ignore window field
	// This prevents a reordered smaller-window packet from permanently blocking
	// the sender after the receiver has already advertised a larger window.
	// Protected by sendMu.
	lastWindowAckSeq uint32
}

func newReliableState(ch *Channel, cfg ReliableCfg) *reliableState {
	cfg = cfg.withDefaults()
	// initPeerWindow is the assumed receiver buffer before the first ACK
	// arrives.  We use the full cfg.WindowSize: both the sender and receiver
	// are configured with the same EventBufSize, and the receiver ring is
	// always rounded up to the next power of 2 (≥ cfg.WindowSize), so the
	// initial burst of cfg.WindowSize events will never overflow the ring.
	// Once the first real ACK arrives, onAck replaces this with the peer's
	// actual advertised window.
	initPeerWindow := cfg.WindowSize
	rs := &reliableState{
		cfg:           cfg,
		channel:       ch,
		nextSeq:       1,
		oldestSeq:     1,
		expectSeq:     1,
		pending:       make([]pendingFrame, cfg.WindowSize),
		peerWindow:    initPeerWindow,
		rto:           cfg.BaseRTO,
		lastAdvWindow: uint32(cfg.WindowSize), // matches peerWindow cap in onAck on the remote side
	}
	rs.cond = sync.NewCond(&rs.sendMu)
	return rs
}

// newAutoReliable creates receive-only reliable state with default config.
// Used when a reliable frame arrives on a channel that hasn't called SetReliable.
func newAutoReliable(ch *Channel) *reliableState {
	return newReliableState(ch, ReliableCfg{})
}

// ── send side ─────────────────────────────────────────────────────────────────

// armRetransmitLocked stops any pending RTO timer and arms a new one with the
// current rs.rto.  The new timer goroutine captures the current epoch; if a
// newer timer is armed before it fires, the goroutine self-aborts.
//
// Must be called with sendMu held.
func (rs *reliableState) armRetransmitLocked() {
	DebugRTOTimerArmed.Add(1)
	if rs.rtoTimer != nil {
		rs.rtoTimer.Stop()
	}
	rs.rtoEpoch++
	epoch := rs.rtoEpoch
	rs.rtoTimer = time.AfterFunc(rs.rto, func() { rs.retransmit(epoch) })
}

// preSend prepares frame for reliable delivery: assigns a sequence number,
// piggybacks any pending ACK from the receive side, saves frame in the
// pending ring, and arms the retransmit timer.
//
// poolSF, when non-nil, is a singleEventFrame from singleEventFramePool that
// owns the Frame.  preSend stores poolSF in the ring slot so that onAck and
// reset can return it to the pool once the frame is ACKed or the session resets.
// Callers that allocate the frame on the heap (e.g. the coalescer) pass nil.
//
// The window is measured in **events** (not frames) to prevent a burst of
// coalesced frames from overflowing the receiver's channel buffer.  A frame
// with N events consumes N window slots; the window opens again when the
// receiver ACKs those events.
//
// It blocks when the send window is full (flow control) and returns
// ErrConnClosed if the channel or connection closes while waiting.
// The caller must call sess.send(frame) after preSend returns nil.
func (rs *reliableState) preSend(frame *Frame, poolSF *singleEventFrame) error {
	// Treat ACK-only frames (no events) as costing 1 window slot so they
	// still participate in flow control and the ring doesn't lose track.
	evtCount := len(frame.Events)
	if evtCount == 0 {
		evtCount = 1
	}
	// Apply the minimum frame cost so that frames with fewer events than
	// eventsPerPacket still consume a full packet's worth of window budget.
	// This prevents the sender from having more frames in-flight than the
	// socket buffer can absorb when coalescing is poor (e.g. 1 event/frame).
	if mc := rs.cfg.MinFrameCost; mc > evtCount {
		evtCount = mc
	}

	rs.sendMu.Lock()
	blocked := false
	for rs.numPending+evtCount > rs.peerWindow {
		if !blocked {
			blocked = true
			DebugPreSendBlocked.Add(1)
		}
		// Window full: block until the receiver ACKs events and frees space.
		// cond.Wait atomically releases sendMu and suspends this goroutine.
		dbg("reliable: send window full, waiting for ACK",
			"channel_id", rs.channel.id,
			"num_pending", rs.numPending,
			"evt_count", evtCount,
			"peer_window", rs.peerWindow,
		)
		// Arm a window probe so that if the receiver's ackBatcher is silent
		// (ackDirty=false — it already sent a full-window ACK and no new
		// frames have arrived since), the probe retransmits the oldest frame
		// to solicit a fresh ACK and break the deadlock.
		rs.armProbeLocked()
		rs.cond.Wait()
		// Check if the channel/conn closed while we were waiting.
		select {
		case <-rs.channel.done:
			rs.sendMu.Unlock()
			return ErrChannelClosed
		case <-rs.channel.conn.done:
			rs.sendMu.Unlock()
			return ErrConnClosed
		default:
		}
	}

	seq := rs.nextSeq
	rs.nextSeq++

	frame.Seq = seq

	// Piggyback any pending ACK from the receive side (free ride on data packets).
	// Fast path (item 7): skip recvMu entirely when ackDirty is false, which is
	// the common case for unidirectional streams.  When true, double-check under
	// recvMu to handle the race where another goroutine cleared ackDirty first.
	if rs.ackDirty.Load() {
		rs.recvMu.Lock()
		if rs.ackDirty.Load() {
			frame.AckSeq = rs.expectSeq
			frame.AckBitmap = rs.ooo
			frame.WindowSize = rs.myWindow()
			rs.ackDirty.Store(false)
			rs.lastAdvWindow = frame.WindowSize
			// Start the window watch whenever we piggyback a restricted window so
			// the remote sender is unblocked as soon as the buffer drains.
			if frame.WindowSize < uint32(rs.cfg.WindowSize) {
				rs.startWindowWatchLocked()
			}
		}
		rs.recvMu.Unlock()
	}

	slot := &rs.pending[seq%uint32(len(rs.pending))]
	slot.seq = seq
	slot.frame = frame
	slot.poolSF = poolSF
	slot.sentAt = time.Now()
	slot.retries = 0
	slot.used = true
	slot.evtCount = evtCount
	rs.numPending += evtCount
	rs.numPendingFast.Store(int32(rs.numPending))

	if !rs.rtoRunning {
		rs.rtoRunning = true
		rs.armRetransmitLocked()
	}
	rs.sendMu.Unlock()
	return nil
}

// onAck processes an incoming ACK: advances the send window and wakes
// blocked senders.
func (rs *reliableState) onAck(ackSeq uint32, bitmap uint64, peerWindow uint32) {
	rs.sendMu.Lock()
	defer rs.sendMu.Unlock()

	freed := 0 // accumulated event count (not frame count) freed this call

	// Cumulative ACK: walk only [oldestSeq, ackSeq) using ring arithmetic.
	// AckSeq == expectSeq on the receiver ("next expected is AckSeq"), so
	// all frames with seq < ackSeq have been received in-order.
	//
	// The walk is O(freed frames) instead of O(cfg.WindowSize).  At high
	// frame rates — e.g. one ACK per frame at 100 K frames/sec with a 4096-
	// entry window — the old O(4096) scan consumed ~400 M pointer reads/sec;
	// the new walk touches only the actually-freed slots.
	ringSize := uint32(len(rs.pending))
	for seq := rs.oldestSeq; seq < ackSeq; seq++ {
		slot := &rs.pending[seq%ringSize]
		if slot.used && slot.seq == seq {
			freed += slot.evtCount
			if slot.poolSF != nil {
				putSingleEventFrame(slot.poolSF)
				slot.poolSF = nil
			}
			slot.used = false
			slot.frame = nil
		}
	}
	dbg("reliable: onAck cumulative freed",
		"channel_id",   rs.channel.id,
		"oldest_seq",   rs.oldestSeq,
		"ack_seq",      ackSeq,
		"freed_events", freed,
	)
	// Only advance oldestSeq forward; ignore stale ACKs (ackSeq ≤ oldestSeq).
	if ackSeq > rs.oldestSeq {
		rs.oldestSeq = ackSeq
	}

	// Free SACK-indicated frames (selective ACK beyond cumulative).
	// The bitmap is uint64 (sackBitmapBits wide); iterating beyond 64 bits
	// would always produce 0 from the shift, so limit to sackBitmapBits.
	if bitmap != 0 {
		for i := 0; i < sackBitmapBits; i++ {
			if bitmap&(1<<uint(i)) != 0 {
				sackSeq := ackSeq + uint32(i) + 1
				slot := &rs.pending[sackSeq%ringSize]
				if slot.used && slot.seq == sackSeq {
					freed += slot.evtCount
					if slot.poolSF != nil {
						putSingleEventFrame(slot.poolSF)
						slot.poolSF = nil
					}
					slot.used = false
					slot.frame = nil
				}
			}
		}
	}

	rs.numPending -= freed
	rs.numPendingFast.Store(int32(rs.numPending))

	// Update peerWindow using TCP-style sequenced rules to prevent a
	// reordered or stale ACK packet from permanently reducing the window.
	//
	// Multiple goroutines (notifyWindowIncreased, windowWatch, preSend
	// piggyback) may call sess.send() concurrently with the same AckSeq but
	// different window values.  On loopback the kernel can serialise those
	// sendmsg calls in any order, so the larger-window packet may arrive
	// first and then be overwritten by the smaller-window packet.
	//
	// Rule: for the same AckSeq (same receiver state) the window can only
	// have grown (the receiver was draining); take the maximum.  Only allow
	// a decrease when AckSeq advances (new events received, buffer can fill).
	oldWindow := rs.peerWindow
	w := int(peerWindow)
	if w > rs.cfg.WindowSize {
		w = rs.cfg.WindowSize
	}
	if ackSeq > rs.lastWindowAckSeq {
		// New receiver state: apply the advertised window unconditionally.
		rs.lastWindowAckSeq = ackSeq
		rs.peerWindow = w
	} else if ackSeq == rs.lastWindowAckSeq {
		// Same receiver state: window can only increase.
		if w > rs.peerWindow {
			rs.peerWindow = w
		}
	}
	// ackSeq < lastWindowAckSeq: stale packet — ignore window field.

	// Wake blocked senders when frames are freed OR the window opens.
	// Both conditions can independently allow a previously-blocked preSend
	// to proceed; broadcasting on window increases handles the case where
	// the receiver drained its buffer and advertised a new non-zero window
	// without any new cumulative ACK (freed == 0).
	if freed > 0 || rs.peerWindow > oldWindow {
		dbg("reliable: ACK freed frames",
			"channel_id",  rs.channel.id,
			"freed",       freed,
			"cum_ack_seq", ackSeq,
			"num_pending", rs.numPending,
			"peer_window", rs.peerWindow,
		)
		rs.stopProbeLocked()
		rs.cond.Broadcast()
	} else {
		DebugOnAckNoUnblock.Add(1)
	}

	// Re-arm or stop retransmit timer.
	if rs.numPending == 0 {
		if rs.rtoTimer != nil {
			rs.rtoTimer.Stop()
			DebugRTOTimerStopped.Add(1)
		}
		rs.rtoRunning = false
	} else if freed > 0 {
		// The window advanced: reset RTO to BaseRTO and re-arm the timer so
		// that the oldest remaining in-flight frame is retransmitted promptly
		// if it goes missing.
		//
		// When freed == 0 (duplicate ACK: AckSeq did not advance and no SACK
		// bits were newly set), we do NOT touch the timer.  Resetting the
		// timer on every duplicate ACK would perpetually postpone the
		// retransmit of a lost frame: the server's ackBatcher fires every
		// ACKDelay (20 ms), so a 200 ms retransmit timer reset on every ACK
		// means the lost frame is never retransmitted.
		earliest := rs.earliestPendingLocked()
		if earliest != nil {
			rs.rto = rs.cfg.BaseRTO
			// Only arm a new timer directly if no retransmit goroutine is
			// in-flight.  If one is, it will re-arm after its send completes
			// using the freshly-reset rto above.
			if !rs.retransmitInFlight {
				rs.armRetransmitLocked()
			}
		}
	}
}

// earliestPendingLocked returns the pending frame with the smallest sentAt.
// Must be called with sendMu held.
//
// Scans [oldestSeq, nextSeq) using ring arithmetic — O(numInFlight frames)
// rather than O(cfg.WindowSize).  Because oldestSeq advances on every
// cumulative ACK, the hot path (one ACK per frame) touches only the
// newly-freed slot(s), making retransmit-timer rearming nearly free.
func (rs *reliableState) earliestPendingLocked() *pendingFrame {
	var earliest *pendingFrame
	ringSize := uint32(len(rs.pending))
	for seq := rs.oldestSeq; seq < rs.nextSeq; seq++ {
		p := &rs.pending[seq%ringSize]
		if p.used && p.seq == seq && (earliest == nil || p.sentAt.Before(earliest.sentAt)) {
			earliest = p
		}
	}
	return earliest
}

// retransmitBatchEntry holds one frame's state stolen from the pending ring
// for the duration of the batch send (outside sendMu).
type retransmitBatchEntry struct {
	frame *Frame
	seq   uint32
	sf    *singleEventFrame
}

// retransmit is called by the AfterFunc timer (via a closure that captures
// epoch).  It retransmits ALL pending frames whose individual RTO has expired
// in a single batch, so that an OS-level burst drop of N packets (e.g. when
// the server goroutine is preempted by SIGURG) causes at most one RTO delay
// rather than N × RTO.
//
// epoch is used to self-abort stale timer goroutines: armRetransmitLocked
// increments rs.rtoEpoch on every arm, and this function aborts if the epoch
// it captured no longer matches rs.rtoEpoch under sendMu.  This prevents a
// "leaked" timer goroutine (one whose rs.rtoTimer pointer was overwritten by a
// later armRetransmitLocked call) from performing spurious retransmits and
// prematurely exhausting MaxRetries.
func (rs *reliableState) retransmit(epoch uint64) {
	rs.sendMu.Lock()

	// Self-abort if this goroutine belongs to a superseded timer.
	if rs.rtoEpoch != epoch {
		DebugRetransmitEpochAbort.Add(1)
		rs.sendMu.Unlock()
		return
	}

	// Prevent goroutine pile-up: if a previous retransmit is still blocked
	// inside sess.send() (waiting for the CC rate limiter), skip this timer
	// fire.  The in-flight goroutine will re-arm the timer once its send
	// completes, using whatever rto (possibly reset by onAck) is current then.
	if rs.retransmitInFlight {
		DebugRetransmitInFlight.Add(1)
		rs.sendMu.Unlock()
		return
	}

	if rs.numPending == 0 {
		DebugRetransmitNumPendingZero.Add(1)
		rs.rtoRunning = false
		rs.sendMu.Unlock()
		return
	}

	DebugRetransmitFired.Add(1)

	// Collect all pending frames whose RTO has expired (sentAt <= now - rto).
	// Use the current rto (before doubling) as the expiry threshold.
	now := time.Now()
	cutoff := now.Add(-rs.rto)
	ringSize := uint32(len(rs.pending))

	// Stack-allocated backing array for small batches; grows to heap only for
	// large windows where many frames expire simultaneously.
	var stackBuf [16]retransmitBatchEntry
	batch := stackBuf[:0]

	maxRetriesSeq := uint32(0)
	maxRetriesHit := false
	for seq := rs.oldestSeq; seq < rs.nextSeq; seq++ {
		p := &rs.pending[seq%ringSize]
		if !p.used || p.seq != seq {
			continue
		}
		if p.sentAt.After(cutoff) {
			continue // RTO not yet expired for this frame
		}
		p.retries++
		rs.retransmits.Add(1)
		if p.retries > rs.cfg.MaxRetries {
			maxRetriesSeq = seq
			maxRetriesHit = true
			break
		}
		p.sentAt = now
		// Steal poolSF: prevents onAck from calling putSingleEventFrame
		// (which clears frame.Events[0]) while sess.send reads it below.
		sf := p.poolSF
		p.poolSF = nil
		batch = append(batch, retransmitBatchEntry{frame: p.frame, seq: seq, sf: sf})
	}

	if maxRetriesHit {
		// Restore poolSFs already stolen before hitting MaxRetries.
		for _, e := range batch {
			if e.sf != nil {
				slot := &rs.pending[e.seq%ringSize]
				if slot.used && slot.seq == e.seq {
					slot.poolSF = e.sf
				} else {
					putSingleEventFrame(e.sf)
				}
			}
		}
		rs.sendMu.Unlock()
		dbg("reliable: max retries exceeded, closing channel",
			"channel_id", rs.channel.id,
			"seq", maxRetriesSeq,
		)
		rs.channel.closeLocal()
		return
	}

	if len(batch) == 0 {
		DebugRetransmitBatchEmpty.Add(1)
		// No expired frames yet — re-arm so the earliest pending frame is
		// checked again after another rto.  armRetransmitLocked increments
		// the epoch, so any concurrent or future timer goroutine from a
		// previous arm will self-abort on the epoch check above.
		if rs.numPending > 0 && rs.rtoRunning {
			rs.armRetransmitLocked()
		}
		rs.sendMu.Unlock()
		return
	}

	// Exponential backoff (once per retransmit round, not per frame).
	rs.rto *= 2
	if rs.rto > maxRTO {
		rs.rto = maxRTO
	}

	// Mark in-flight BEFORE unlocking.  Do NOT arm the next timer here —
	// arming it after all sends complete prevents goroutine pile-up when the
	// CC rate limiter blocks for longer than the current RTO.
	rs.retransmitInFlight = true
	rs.sendMu.Unlock()

	// Re-send all expired frames outside the lock.
	// sess.send re-encrypts each with a fresh nonce.
	sess := rs.channel.conn.sessionFast()
	for _, e := range batch {
		if sess != nil {
			dbg("reliable: retransmitting frame",
				"channel_id", rs.channel.id,
				"seq", e.frame.Seq,
				"rto", rs.rto,
			)
			DebugRetransmitSent.Add(1)
			if err := sess.send(e.frame); err != nil {
				DebugRetransmitSendErr.Add(1)
			}
		} else {
			DebugRetransmitSessNil.Add(1)
		}
	}

	// Re-arm the retransmit timer now that all sends have completed.
	// Clear the in-flight flag so the next timer fire can proceed.
	// Use rs.rto as-is: onAck may have reset it to BaseRTO while we were
	// blocked, giving the correct (shorter) next timeout.
	rs.sendMu.Lock()
	rs.retransmitInFlight = false

	// Restore poolSF for each batch entry.  If a slot was ACKed (or reset)
	// while we held its poolSF, free the singleEventFrame here instead.
	for _, e := range batch {
		if e.sf != nil {
			slot := &rs.pending[e.seq%ringSize]
			if slot.used && slot.seq == e.seq {
				slot.poolSF = e.sf // restore; onAck/reset will free it
			} else {
				putSingleEventFrame(e.sf) // freed while we held it
			}
		}
	}

	if rs.numPending > 0 && rs.rtoRunning {
		rs.armRetransmitLocked()
	} else {
		DebugRetransmitRearmSkipped.Add(1)
	}
	rs.sendMu.Unlock()
}

// ── window probe ──────────────────────────────────────────────────────────────

// armProbeLocked starts the window-probe timer if not already active.
// The probe fires after cfg.BaseRTO and either retransmits the oldest pending
// frame (numPending > 0) or sends a deliberate-duplicate frame (numPending == 0)
// to elicit a fresh window advertisement from the receiver.
// Must be called with sendMu held.
func (rs *reliableState) armProbeLocked() {
	if rs.probeRunning {
		return
	}
	rs.probeRunning = true
	rs.probeEpoch++
	epoch := rs.probeEpoch
	time.AfterFunc(rs.cfg.BaseRTO, func() { rs.sendWindowProbe(epoch) })
}

// stopProbeLocked cancels any pending probe by bumping the epoch so that the
// goroutine scheduled by armProbeLocked self-aborts on the mismatch.
// Must be called with sendMu held.
func (rs *reliableState) stopProbeLocked() {
	if rs.probeRunning {
		rs.probeEpoch++ // stale goroutine will self-abort on epoch mismatch
		rs.probeRunning = false
	}
}

// sendWindowProbe is the AfterFunc callback for the window-probe timer.
// It sends the oldest pending frame without incrementing p.retries (so the
// channel is never closed because of a flow-control stall) and re-arms itself
// if the sender is still blocked.
func (rs *reliableState) sendWindowProbe(epoch uint64) {
	rs.sendMu.Lock()
	if rs.probeEpoch != epoch {
		rs.sendMu.Unlock()
		return
	}
	if rs.numPending == 0 {
		// All sent frames have been ACKed, but peerWindow is still too small
		// for the next frame (e.g. a transient small-window ACK arrived just
		// as the last pending frame was freed).  Send a deliberate-duplicate
		// frame (seq = nextSeq-1) so the receiver sets ackDirty = true and
		// the ackBatcher sends back an ACK with the current receive window.
		// nextSeq > 1 here because peerWindow == cfg.WindowSize when nextSeq
		// == 1 (initial state), so preSend cannot block before any frame is sent.
		probeSeq := rs.nextSeq - 1
		rs.sendMu.Unlock()

		sess := rs.channel.conn.sessionFast()
		if sess != nil {
			f := ackFramePool.Get().(*Frame)
			f.ChannelId = rs.channel.id
			f.Seq = probeSeq
			DebugProbesFired.Add(1)
			_ = sess.send(f)
			*f = Frame{}
			ackFramePool.Put(f)
		}

		// Re-arm if not cancelled by onAck/reset while we were outside the lock.
		rs.sendMu.Lock()
		if rs.probeEpoch == epoch {
			rs.probeEpoch++
			newEpoch := rs.probeEpoch
			time.AfterFunc(rs.cfg.BaseRTO, func() { rs.sendWindowProbe(newEpoch) })
		}
		rs.sendMu.Unlock()
		return
	}
	p := rs.earliestPendingLocked()
	if p == nil {
		rs.probeRunning = false
		rs.sendMu.Unlock()
		return
	}
	frame := p.frame
	seq := p.seq
	// Steal poolSF to prevent onAck from calling putSingleEventFrame (which
	// clears frame.Events[0]) while sess.send is reading the frame below.
	// Mirrors the pattern used in retransmit().
	sf := p.poolSF
	p.poolSF = nil
	rs.retransmits.Add(1)
	rs.sendMu.Unlock()

	sess := rs.channel.conn.sessionFast()
	if sess != nil {
		dbg("reliable: window probe (no retry increment)",
			"channel_id", rs.channel.id,
			"seq", frame.Seq,
		)
		DebugProbesFired.Add(1)
		_ = sess.send(frame)
	}

	// Restore poolSF; free it if onAck already freed the slot while we held it.
	rs.sendMu.Lock()
	ringSize := uint32(len(rs.pending))
	slot := &rs.pending[seq%ringSize]
	if slot.used && slot.seq == seq {
		slot.poolSF = sf
	} else if sf != nil {
		putSingleEventFrame(sf)
	}
	// Re-arm the probe if it was not cancelled by onAck/reset while we were
	// outside the lock.  Bump the epoch so the old closure self-aborts.
	if rs.probeEpoch == epoch {
		rs.probeEpoch++
		newEpoch := rs.probeEpoch
		time.AfterFunc(rs.cfg.BaseRTO, func() { rs.sendWindowProbe(newEpoch) })
	}
	rs.sendMu.Unlock()
}

// ── receive side ──────────────────────────────────────────────────────────────

// onRecv handles an incoming reliable frame: delivers it if in-order, or
// buffers it for later delivery when the gap is filled.
func (rs *reliableState) onRecv(seq uint32, f *Frame) {
	rs.recvMu.Lock()

	// Re-check after acquiring recvMu: SetReliable holds old.recvMu across
	// its state copy AND Store, so if the new state was stored before we
	// acquired the lock, we will see it here and forward.  This, combined with
	// SetReliable holding the lock during Store, guarantees that ackDirty set
	// by onRecv is always visible to the ackBatcher via the current state.
	if current := rs.channel.reliable.Load(); current != nil && current != rs {
		rs.recvMu.Unlock()
		current.onRecv(seq, f)
		return
	}

	switch {
	case seq == rs.expectSeq:
		// In-order: deliver this frame and any consecutive buffered OOO frames.
		// Keep recvMu held throughout to prevent a concurrent worker from
		// delivering the next in-sequence frame to ch.events out of order.
		DebugOnRecvInOrder.Add(1)
		rs.deliverInOrderLocked(f)
		rs.recvMu.Unlock()
		return

	case seq > rs.expectSeq:
		gap := seq - rs.expectSeq
		if gap <= reliableOOOWindow {
			// Circular-buffer slot: slot for gap g is at (oooHead+g-1) % N.
			idx := (rs.oooHead + int(gap) - 1) % reliableOOOWindow
			if rs.oooFrames[idx] == nil {
				rs.oooFrames[idx] = f
				// The SACK bitmap (uint64) can only represent the first 64
				// OOO slots.  Frames beyond that are still buffered and will
				// be delivered once the window slides; they are just not
				// selectively acknowledged until the cumulative ACK catches up.
				if gap <= sackBitmapBits {
					rs.ooo |= 1 << (gap - 1)
				}
				dbg("reliable: buffering out-of-order frame",
					"channel_id", rs.channel.id,
					"seq",        seq,
					"expected",   rs.expectSeq,
					"gap",        gap,
					"slot",       idx,
					"ooo_head",   rs.oooHead,
				)
			}
			// else duplicate — drop
		} else {
			dbg("reliable: OOO frame too far ahead, dropping",
				"channel_id", rs.channel.id,
				"seq",        seq,
				"expected",   rs.expectSeq,
				"gap",        gap,
			)
			DebugOOOTooFar.Add(1)
		}

	default:
		// seq < expectSeq: duplicate — drop
		dbg("reliable: duplicate in-order frame dropped",
			"channel_id", rs.channel.id,
			"seq",        seq,
			"expected",   rs.expectSeq,
		)
		DebugOnRecvDuplicate.Add(1)
	}

	rs.ackDirty.Store(true)
	rs.recvMu.Unlock()
}

// deliverInOrderLocked delivers f (which has seq == expectSeq) and then
// advances through any consecutively buffered OOO frames.  Must be called
// WITH recvMu held; returns with recvMu held.
//
// All delivery to ch.events happens while the mutex is held, which prevents
// a concurrent worker from pushing events for the next in-sequence frame
// before this frame's events have been enqueued (ordering safety).
// deliverEventToChannel is non-blocking (drop-oldest on overflow), so holding
// recvMu during delivery cannot deadlock.
func (rs *reliableState) deliverInOrderLocked(f *Frame) {
	// Deliver this frame's events while holding recvMu.
	for _, e := range f.Events {
		if e.Type == channelCloseType {
			rs.channel.closeLocal()
		} else {
			deliverEventToChannel(rs.channel, e)
		}
	}
	rs.expectSeq++

	// Drain any consecutively buffered OOO frames using O(1) circular-buffer
	// head rotation.  Each advance costs one nil-check plus one slot clear,
	// replacing the previous O(N) memmove (copy of the entire oooFrames array).
	// oooHead always points to the slot for the current expectSeq; advancing
	// it by 1 (mod N) makes the next slot current, without copying anything.
	drained := 0
	for {
		slot := rs.oooHead
		next := rs.oooFrames[slot]
		// Always advance the circular-buffer head and shift the SACK bitmap,
		// whether or not there is a consecutive OOO frame at this slot.
		//
		// Invariant: oooHead is the slot for gap=1 (seq=expectSeq+1) from the
		// CURRENT expectSeq.  When deliverInOrderLocked advances expectSeq by 1
		// for each in-order or OOO frame delivered, oooHead must advance in
		// lock-step so that stored OOO frames remain at the correct slot for
		// their updated gap.
		//
		// Without this advance, an in-order delivery that finds nil at oooHead
		// (no consecutive OOO frame) would leave oooHead un-advanced.  Any OOO
		// frame stored at gap > 1 from the old expectSeq is then 1 slot too far
		// from the new oooHead, making it invisible to the drain loop when the
		// gap eventually shrinks to 1.  The server would have freed that frame
		// via SACK (believing the client received it in OOO), so it would never
		// retransmit it — permanently losing the events it carried.
		rs.oooHead = (rs.oooHead + 1) % reliableOOOWindow
		rs.ooo >>= 1 // keep SACK bitmap in sync with window position
		if next == nil {
			break
		}
		rs.oooFrames[slot] = nil
		rs.expectSeq++
		drained++
		for _, e := range next.Events {
			if e.Type == channelCloseType {
				rs.channel.closeLocal()
			} else {
				deliverEventToChannel(rs.channel, e)
			}
		}
	}
	if drained > 0 {
		dbg("reliable: drained OOO frames (circular head advance)",
			"channel_id", rs.channel.id,
			"drained",    drained,
			"expect_seq", rs.expectSeq,
			"ooo_head",   rs.oooHead,
		)
	}

	rs.ackDirty.Store(true)
	// The per-Conn ackBatcher goroutine will send a standalone ACK within
	// one batcher tick (defaultACKDelay) if no piggybacking opportunity arises.
}

// myWindow returns the number of slots available in the receive channel buffer,
// capped at cfg.WindowSize.  The cap ensures the advertised window never
// exceeds what the remote sender can actually use: onAck on the remote side
// clamps peerWindow to cfg.WindowSize, so advertising more than cfg.WindowSize
// free slots is meaningless and would cause the "last advertised = full"
// sentinel (lastAdvWindow == cfg.WindowSize) to be set correctly.
// Must be called with recvMu held (reads channel state without extra lock).
func (rs *reliableState) myWindow() uint32 {
	cap := rs.channel.ring.Cap()
	used := rs.channel.ring.Len()
	avail := cap - used
	if avail < 0 {
		avail = 0
	}
	if avail > rs.cfg.WindowSize {
		avail = rs.cfg.WindowSize
	}
	return uint32(avail)
}

// sendACK sends a standalone ACK frame back to the remote peer.
// Called by the ackBatcher goroutine; runs in the batcher's goroutine.
func (rs *reliableState) sendACK() {
	rs.recvMu.Lock()
	if !rs.ackDirty.Load() {
		rs.recvMu.Unlock()
		return
	}
	cumAck := rs.expectSeq
	bitmap := rs.ooo
	window := rs.myWindow()
	rs.ackDirty.Store(false)
	rs.lastAdvWindow = window
	// Start the window watch whenever we advertise a restricted window.
	// A restricted window (< receiver capacity) means the remote sender may
	// block if its next frame's evtCount exceeds our advertised window.
	// The watch polls every millisecond and sends an immediate update as soon
	// as the application drains events and myWindow() grows.  This covers
	// both window=0 and non-zero restricted windows that can still deadlock
	// the sender (e.g. peerWindow=1 with evtCount=63).
	if window < uint32(rs.cfg.WindowSize) {
		rs.startWindowWatchLocked()
	}
	rs.recvMu.Unlock()

	sess := rs.channel.conn.sessionFast()
	if sess == nil {
		return
	}
	// Pool ACK-only frames: they have no events and are immediately done after
	// sess.send() returns, so the pool object is safe to reuse right away.
	ackFrame := ackFramePool.Get().(*Frame)
	ackFrame.ChannelId = rs.channel.id
	ackFrame.AckSeq = cumAck
	ackFrame.AckBitmap = bitmap
	ackFrame.WindowSize = window
	dbg("reliable: sending ACK",
		"channel_id", rs.channel.id,
		"ack_seq", cumAck,
		"window", window,
	)
	_ = sess.send(ackFrame)
	*ackFrame = Frame{} // clear all fields before returning to pool
	ackFramePool.Put(ackFrame)
}

// startWindowWatchLocked arms the window-watch timer if not already running.
// Must be called with recvMu held.
func (rs *reliableState) startWindowWatchLocked() {
	if rs.windowWatchActive {
		return
	}
	rs.windowWatchActive = true
	time.AfterFunc(time.Millisecond, rs.windowWatch)
}

// windowWatch is the periodic callback that checks whether the application has
// drained enough events from ch.events to open the receive window.  When the
// window becomes positive we immediately send a window-update ACK so the remote
// sender is unblocked without waiting for the full ACKDelay (20 ms by default).
func (rs *reliableState) windowWatch() {
	// Stop if the channel or connection is gone.
	select {
	case <-rs.channel.done:
		rs.recvMu.Lock()
		rs.windowWatchActive = false
		rs.recvMu.Unlock()
		return
	case <-rs.channel.conn.done:
		rs.recvMu.Lock()
		rs.windowWatchActive = false
		rs.recvMu.Unlock()
		return
	default:
	}

	rs.recvMu.Lock()
	maxCap := uint32(rs.cfg.WindowSize) // matches peerWindow cap in onAck on the remote side
	if rs.myWindow() > rs.lastAdvWindow {
		// Window has grown beyond what we last advertised — send an immediate
		// update so the remote sender can unblock without waiting for ACKDelay.
		rs.windowWatchActive = false
		rs.ackDirty.Store(true)
		rs.recvMu.Unlock()
		rs.sendACK()
		return
	}
	// Stop the watch if the last advertised window already equals full capacity:
	// a concurrent sendACK sent a full-window update, nothing left to do.
	if rs.lastAdvWindow >= maxCap {
		rs.windowWatchActive = false
		rs.recvMu.Unlock()
		return
	}
	// Window hasn't grown yet — reschedule poll.
	time.AfterFunc(time.Millisecond, rs.windowWatch)
	rs.recvMu.Unlock()
}

// notifyWindowIncreased is called by Channel.Recv (and Conn.Recv) after the
// application drains one event from ch.events.  If the receive window has
// grown beyond what we last advertised AND the last advertised value was
// restricted (< full capacity), we immediately send a window-update ACK so
// the remote sender can unblock without waiting for the ACKDelay timer.
//
// This handles the case where the sender's frame evtCount exceeds the last
// advertised window (e.g. peerWindow=1, evtCount=63): the sender blocks in
// preSend indefinitely because no new frame arrives to trigger ackDirty, and
// the window watch only activates for window=0.  Proactive updates from the
// receiver break this deadlock in O(evtCount) Recv calls.
func (rs *reliableState) notifyWindowIncreased() {
	rs.recvMu.Lock()
	w := rs.myWindow()
	// Only update if the window genuinely grew AND was previously restricted.
	// lastAdvWindow is initialised to cfg.WindowSize (== the sender's peerWindow
	// cap), so this is a no-op until we have actually advertised a smaller
	// window to the peer.
	maxCap := uint32(rs.cfg.WindowSize)
	if w <= rs.lastAdvWindow || rs.lastAdvWindow >= maxCap {
		rs.recvMu.Unlock()
		return
	}
	// Window has grown from a restricted state: send an immediate update.
	rs.ackDirty.Store(true)
	rs.recvMu.Unlock()
	rs.sendACK()
}

// waitEmpty blocks until all sent frames have been ACKed by the remote peer,
// or until ctx is cancelled (e.g. a drain timeout).  It is used by Conn.Close
// to ensure reliable data is delivered before the disconnect packet is sent.
func (rs *reliableState) waitEmpty(ctx context.Context) error {
	// A goroutine watches ctx and broadcasts on the cond so that cond.Wait
	// returns when the context expires, not only when frames are ACKed.
	watchDone := make(chan struct{})
	defer close(watchDone)
	go func() {
		select {
		case <-ctx.Done():
			rs.cond.Broadcast()
		case <-watchDone:
		}
	}()

	rs.sendMu.Lock()
	defer rs.sendMu.Unlock()
	if rs.numPending > 0 {
		dbg("reliable: drain waiting for ACKs",
			"channel_id",  rs.channel.id,
			"num_pending", rs.numPending,
		)
	}
	for rs.numPending > 0 {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		rs.cond.Wait()
	}
	return nil
}

// reset clears all pending send-side state and wakes blocked senders.
// Called when the underlying session closes (persistent reconnect or permanent close).
func (rs *reliableState) reset() {
	DebugReliableReset.Add(1)
	dbg("reliable: resetting state",
		"channel_id",  rs.channel.id,
		"num_pending", rs.numPending,
	)
	rs.sendMu.Lock()
	// Free all pending frames; return any pool-owned frames to their pool.
	for i := range rs.pending {
		if rs.pending[i].poolSF != nil {
			putSingleEventFrame(rs.pending[i].poolSF)
			rs.pending[i].poolSF = nil
		}
		rs.pending[i].used = false
		rs.pending[i].frame = nil
	}
	rs.numPending = 0
	rs.numPendingFast.Store(0)
	rs.nextSeq = 1
	rs.oldestSeq = 1
	rs.lastWindowAckSeq = 0
	rs.peerWindow = rs.cfg.WindowSize
	rs.rto = rs.cfg.BaseRTO
	rs.retransmits.Store(0)
	if rs.rtoTimer != nil {
		rs.rtoTimer.Stop()
		rs.rtoRunning = false
	}
	rs.stopProbeLocked()
	rs.cond.Broadcast()
	rs.sendMu.Unlock()

	rs.recvMu.Lock()
	rs.expectSeq = 1
	rs.ooo = 0
	rs.oooHead = 0
	for i := range rs.oooFrames {
		rs.oooFrames[i] = nil
	}
	rs.ackDirty.Store(false)
	rs.recvMu.Unlock()
}

// deliverEventToChannel pushes an event into the channel's ring buffer.
// For reliable channels, flow control ensures the ring is never full in normal
// operation.  On overflow, the newest event is dropped (drop-newest policy).
func deliverEventToChannel(ch *Channel, e *Event) {
	dbg("deliver event", "channel_id", ch.id, "type", e.Type)
	if !ch.ring.push(e) {
		dbg("reliable: channel buffer full, dropping event", "channel_id", ch.id)
		DebugRingDropped.Add(1)
	} else {
		DebugEventsDelivered.Add(1)
	}
}
