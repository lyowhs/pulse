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
	nextSeq    uint32        // next sequence number to assign (starts at 1)
	pending    []pendingFrame // ring buffer; len == cfg.WindowSize; indexed by seq % len
	numPending int           // total events (not frames) currently in-flight
	peerWindow int           // receiver-advertised window in events; starts at cfg.WindowSize
	cond       *sync.Cond     // wait when numPending >= peerWindow
	rtoRunning        bool          // true while rtoTimer is armed or retransmit is in-flight
	rto               time.Duration // current RTO (doubles on retransmit)
	rtoTimer          *time.Timer
	retransmitInFlight bool         // true while retransmit() goroutine is blocked in sess.send()

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
	oooHead  int
	ackDirty bool
	ackTimer *time.Timer

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
	// arrives.  Cap at defaultReliableWindow so the initial burst does not
	// exceed what a peer with a smaller window can absorb.  Once the first
	// real ACK arrives, onAck replaces this with the peer's actual window.
	initPeerWindow := cfg.WindowSize
	if initPeerWindow > defaultReliableWindow {
		initPeerWindow = defaultReliableWindow
	}
	rs := &reliableState{
		cfg:           cfg,
		channel:       ch,
		nextSeq:       1,
		expectSeq:     1,
		pending:       make([]pendingFrame, cfg.WindowSize),
		peerWindow:    initPeerWindow,
		rto:           cfg.BaseRTO,
		lastAdvWindow: uint32(cap(ch.events)), // assume full receiver capacity until first ACK
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

// preSend prepares frame for reliable delivery: assigns a sequence number,
// piggybacks any pending ACK from the receive side, saves frame in the
// pending ring, and arms the retransmit timer.
//
// The window is measured in **events** (not frames) to prevent a burst of
// coalesced frames from overflowing the receiver's channel buffer.  A frame
// with N events consumes N window slots; the window opens again when the
// receiver ACKs those events.
//
// It blocks when the send window is full (flow control) and returns
// ErrConnClosed if the channel or connection closes while waiting.
// The caller must call sess.send(frame) after preSend returns nil.
func (rs *reliableState) preSend(frame *Frame) error {
	// Treat ACK-only frames (no events) as costing 1 window slot so they
	// still participate in flow control and the ring doesn't lose track.
	evtCount := len(frame.Events)
	if evtCount == 0 {
		evtCount = 1
	}

	rs.sendMu.Lock()
	for rs.numPending+evtCount > rs.peerWindow {
		// Window full: block until the receiver ACKs events and frees space.
		// cond.Wait atomically releases sendMu and suspends this goroutine.
		dbg("reliable: send window full, waiting for ACK",
			"channel_id", rs.channel.id,
			"num_pending", rs.numPending,
			"evt_count", evtCount,
			"peer_window", rs.peerWindow,
		)
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
	rs.recvMu.Lock()
	if rs.ackDirty {
		frame.AckSeq = rs.expectSeq
		frame.AckBitmap = rs.ooo
		frame.WindowSize = rs.myWindow()
		rs.ackDirty = false
		rs.lastAdvWindow = frame.WindowSize
		if rs.ackTimer != nil {
			rs.ackTimer.Stop()
			rs.ackTimer = nil
		}
		// Start the window watch whenever we piggyback a restricted window so
		// the remote sender is unblocked as soon as the buffer drains.
		if frame.WindowSize < uint32(cap(rs.channel.events)) {
			rs.startWindowWatchLocked()
		}
	}
	rs.recvMu.Unlock()

	slot := &rs.pending[seq%uint32(len(rs.pending))]
	slot.seq = seq
	slot.frame = frame
	slot.sentAt = time.Now()
	slot.retries = 0
	slot.used = true
	slot.evtCount = evtCount
	rs.numPending += evtCount

	if !rs.rtoRunning {
		rs.rtoRunning = true
		rs.rtoTimer = time.AfterFunc(rs.rto, rs.retransmit)
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

	// Free all frames with seq < ackSeq (cumulative ACK).
	// AckSeq == expectSeq on the receiver, meaning "next expected is AckSeq",
	// so all seq < AckSeq have been received in-order.
	// numPending tracks events; iterate by seq (frames) but accumulate evtCount.
	ringSize := uint32(len(rs.pending))
	// Compute the oldest in-flight seq: frames are stored starting at
	// (nextSeq - numFramesInFlight), but numPending is in events so we scan
	// the whole ring for used+seq<ackSeq entries.
	for i := range rs.pending {
		slot := &rs.pending[i]
		if !slot.used || slot.seq >= ackSeq {
			continue
		}
		freed += slot.evtCount
		slot.used = false
		slot.frame = nil
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
					slot.used = false
					slot.frame = nil
				}
			}
		}
	}

	rs.numPending -= freed

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
		rs.cond.Broadcast()
	}

	// Re-arm or stop retransmit timer.
	if rs.numPending == 0 {
		if rs.rtoTimer != nil {
			rs.rtoTimer.Stop()
		}
		rs.rtoRunning = false
	} else {
		earliest := rs.earliestPendingLocked()
		if earliest != nil {
			rs.rto = rs.cfg.BaseRTO
			if rs.rtoTimer != nil {
				rs.rtoTimer.Stop()
				rs.rtoTimer = nil
			}
			// Only arm a new timer directly if no retransmit goroutine is
			// in-flight.  If one is, it will re-arm after its send completes
			// using the freshly-reset rto above.
			if !rs.retransmitInFlight {
				rs.rtoTimer = time.AfterFunc(rs.rto, rs.retransmit)
			}
		}
	}
}

// earliestPendingLocked returns the pending frame with the smallest sentAt.
// Must be called with sendMu held.
func (rs *reliableState) earliestPendingLocked() *pendingFrame {
	var earliest *pendingFrame
	for i := range rs.pending {
		p := &rs.pending[i]
		if p.used && (earliest == nil || p.sentAt.Before(earliest.sentAt)) {
			earliest = p
		}
	}
	return earliest
}

// retransmit is called by the AfterFunc timer.  It retransmits the oldest
// unACKed frame with exponential RTO backoff.
func (rs *reliableState) retransmit() {
	rs.sendMu.Lock()

	// Prevent goroutine pile-up: if a previous retransmit is still blocked
	// inside sess.send() (waiting for the CC rate limiter), skip this timer
	// fire.  The in-flight goroutine will re-arm the timer once its send
	// completes, using whatever rto (possibly reset by onAck) is current then.
	if rs.retransmitInFlight {
		rs.sendMu.Unlock()
		return
	}

	if rs.numPending == 0 {
		rs.rtoRunning = false
		rs.sendMu.Unlock()
		return
	}

	p := rs.earliestPendingLocked()
	if p == nil {
		rs.rtoRunning = false
		rs.sendMu.Unlock()
		return
	}

	p.retries++
	rs.retransmits.Add(1)
	if p.retries > rs.cfg.MaxRetries {
		rs.sendMu.Unlock()
		dbg("reliable: max retries exceeded, closing channel",
			"channel_id", rs.channel.id,
			"seq", p.seq,
			"retries", p.retries,
		)
		rs.channel.closeLocal()
		return
	}

	// Exponential backoff.
	rs.rto *= 2
	if rs.rto > maxRTO {
		rs.rto = maxRTO
	}
	p.sentAt = time.Now()
	frame := p.frame

	// Mark in-flight BEFORE unlocking.  Do NOT arm the next timer here —
	// arming it after sess.send() returns prevents goroutine pile-up when the
	// CC rate limiter blocks the send for longer than the current RTO.
	rs.retransmitInFlight = true
	rs.sendMu.Unlock()

	// Re-send outside the lock.  sess.send re-encrypts with a fresh nonce.
	if sess := rs.channel.conn.sessionFast(); sess != nil {
		dbg("reliable: retransmitting frame",
			"channel_id", rs.channel.id,
			"seq", frame.Seq,
			"rto", rs.rto,
		)
		_ = sess.send(frame)
	}

	// Re-arm the retransmit timer now that the (potentially rate-limited)
	// send has completed.  Clear the in-flight flag so the next timer fire
	// can proceed.  Use rs.rto as-is: onAck may have reset it to BaseRTO
	// while we were blocked, giving us the correct (shorter) next timeout.
	rs.sendMu.Lock()
	rs.retransmitInFlight = false
	if rs.numPending > 0 && rs.rtoRunning {
		rs.rtoTimer = time.AfterFunc(rs.rto, rs.retransmit)
	}
	rs.sendMu.Unlock()
}

// ── receive side ──────────────────────────────────────────────────────────────

// onRecv handles an incoming reliable frame: delivers it if in-order, or
// buffers it for later delivery when the gap is filled.
func (rs *reliableState) onRecv(seq uint32, f *Frame) {
	rs.recvMu.Lock()

	switch {
	case seq == rs.expectSeq:
		// In-order: deliver this frame and any consecutive buffered OOO frames.
		// Keep recvMu held throughout to prevent a concurrent worker from
		// delivering the next in-sequence frame to ch.events out of order.
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
		}

	default:
		// seq < expectSeq: duplicate — drop
		dbg("reliable: duplicate in-order frame dropped",
			"channel_id", rs.channel.id,
			"seq",        seq,
			"expected",   rs.expectSeq,
		)
	}

	rs.ackDirty = true
	rs.scheduleACKLocked()
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
		if next == nil {
			break
		}
		rs.oooFrames[slot] = nil
		rs.oooHead = (rs.oooHead + 1) % reliableOOOWindow
		rs.ooo >>= 1 // keep SACK bitmap in sync with window position
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

	rs.ackDirty = true
	rs.scheduleACKLocked()
}

// myWindow returns the number of slots available in the receive channel buffer.
// Must be called with recvMu held (reads channel state without extra lock).
func (rs *reliableState) myWindow() uint32 {
	cap := cap(rs.channel.events)
	used := len(rs.channel.events)
	avail := cap - used
	if avail < 0 {
		avail = 0
	}
	return uint32(avail)
}

// scheduleACKLocked arms the delayed-ACK timer if not already running.
// Must be called with recvMu held.
func (rs *reliableState) scheduleACKLocked() {
	if rs.ackTimer == nil {
		rs.ackTimer = time.AfterFunc(rs.cfg.ACKDelay, rs.sendACK)
	}
}

// sendACK sends a standalone ACK frame back to the remote peer.
// Called by the ackTimer AfterFunc; runs in its own goroutine.
func (rs *reliableState) sendACK() {
	rs.recvMu.Lock()
	if !rs.ackDirty {
		rs.ackTimer = nil
		rs.recvMu.Unlock()
		return
	}
	cumAck := rs.expectSeq
	bitmap := rs.ooo
	window := rs.myWindow()
	rs.ackDirty = false
	rs.ackTimer = nil
	rs.lastAdvWindow = window
	// Start the window watch whenever we advertise a restricted window.
	// A restricted window (< receiver capacity) means the remote sender may
	// block if its next frame's evtCount exceeds our advertised window.
	// The watch polls every millisecond and sends an immediate update as soon
	// as the application drains events and myWindow() grows.  This covers
	// both window=0 and non-zero restricted windows that can still deadlock
	// the sender (e.g. peerWindow=1 with evtCount=63).
	if window < uint32(cap(rs.channel.events)) {
		rs.startWindowWatchLocked()
	}
	rs.recvMu.Unlock()

	sess := rs.channel.conn.sessionFast()
	if sess == nil {
		return
	}
	ackFrame := &Frame{
		ChannelId:  rs.channel.id,
		AckSeq:     cumAck,
		AckBitmap:  bitmap,
		WindowSize: window,
	}
	dbg("reliable: sending ACK",
		"channel_id", rs.channel.id,
		"ack_seq", cumAck,
		"window", window,
	)
	_ = sess.send(ackFrame)
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
	maxCap := uint32(cap(rs.channel.events))
	if rs.myWindow() > rs.lastAdvWindow {
		// Window has grown beyond what we last advertised — send an immediate
		// update so the remote sender can unblock without waiting for ACKDelay.
		rs.windowWatchActive = false
		rs.ackDirty = true
		if rs.ackTimer != nil {
			rs.ackTimer.Stop()
			rs.ackTimer = nil
		}
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
	// lastAdvWindow is initialised to cfg.WindowSize, so this is a no-op until
	// we have actually advertised a smaller window to the peer.
	maxCap := uint32(cap(rs.channel.events))
	if w <= rs.lastAdvWindow || rs.lastAdvWindow >= maxCap {
		rs.recvMu.Unlock()
		return
	}
	// Window has grown from a restricted state: send an immediate update.
	rs.ackDirty = true
	if rs.ackTimer != nil {
		rs.ackTimer.Stop()
		rs.ackTimer = nil
	}
	rs.recvMu.Unlock()
	rs.sendACK()
}

// consumePendingACK reads and clears any pending ACK state for piggybacking.
// Returns (cumAck, bitmap, window, true) if an ACK is pending, or (0,0,0,false).
// Must NOT be called with recvMu held.
func (rs *reliableState) consumePendingACK() (cumAck uint32, bitmap uint64, window uint32, ok bool) {
	rs.recvMu.Lock()
	if !rs.ackDirty {
		rs.recvMu.Unlock()
		return 0, 0, 0, false
	}
	cumAck = rs.expectSeq
	bitmap = rs.ooo
	window = rs.myWindow()
	rs.ackDirty = false
	if rs.ackTimer != nil {
		rs.ackTimer.Stop()
		rs.ackTimer = nil
	}
	// Start the window watch whenever we piggyback a restricted window.
	if window < uint32(cap(rs.channel.events)) {
		rs.startWindowWatchLocked()
	}
	rs.recvMu.Unlock()
	return cumAck, bitmap, window, true
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
	dbg("reliable: resetting state",
		"channel_id",  rs.channel.id,
		"num_pending", rs.numPending,
	)
	rs.sendMu.Lock()
	// Free all pending frames.
	for i := range rs.pending {
		rs.pending[i].used = false
		rs.pending[i].frame = nil
	}
	rs.numPending = 0
	rs.nextSeq = 1
	rs.peerWindow = rs.cfg.WindowSize
	rs.rto = rs.cfg.BaseRTO
	rs.retransmits.Store(0)
	if rs.rtoTimer != nil {
		rs.rtoTimer.Stop()
		rs.rtoRunning = false
	}
	rs.cond.Broadcast()
	rs.sendMu.Unlock()

	rs.recvMu.Lock()
	rs.expectSeq = 1
	rs.ooo = 0
	rs.oooHead = 0
	for i := range rs.oooFrames {
		rs.oooFrames[i] = nil
	}
	rs.ackDirty = false
	if rs.ackTimer != nil {
		rs.ackTimer.Stop()
		rs.ackTimer = nil
	}
	rs.recvMu.Unlock()
}

// deliverEventToChannel pushes an event into the channel's receive buffer.
// Mirrors the delivery logic from conn.go (drop-oldest on overflow).
func deliverEventToChannel(ch *Channel, e *Event) {
	select {
	case ch.events <- e:
	default:
		dbg("reliable: channel buffer full, dropping oldest event", "channel_id", ch.id)
		select {
		case <-ch.events:
		default:
		}
		select {
		case ch.events <- e:
		default:
		}
	}
}
