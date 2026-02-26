package wiresocket

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultReliableWindow  = 256
	defaultBaseRTO         = 200 * time.Millisecond
	defaultMaxRetries      = 10
	defaultACKDelay        = 20 * time.Millisecond
	maxRTO                 = 30 * time.Second
	reliableOOOWindow      = 64 // must equal the bitmap width
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
	seq     uint32
	frame   *Frame    // immutable once stored; re-sent as-is on retransmit
	sentAt  time.Time
	retries int
	used    bool
}

// reliableState is the per-channel reliability and flow-control state.
// It is attached to Channel.reliable; nil means unreliable (zero overhead).
type reliableState struct {
	cfg     ReliableCfg
	channel *Channel // back-reference for sending ACKs and closing channel

	// ── send side ─────────────────────────────────────────────────────────
	sendMu     sync.Mutex
	nextSeq    uint32          // next sequence number to assign (starts at 1)
	pending    [256]pendingFrame
	numPending int
	peerWindow int             // receiver-advertised window; starts at cfg.WindowSize
	cond       *sync.Cond     // wait when numPending >= peerWindow
	rtoRunning bool            // true while rtoTimer is armed
	rto        time.Duration   // current RTO (doubles on retransmit)
	rtoTimer   *time.Timer

	// retransmits counts the total number of frame retransmit events since
	// this reliableState was created or last reset.
	retransmits atomic.Int64

	// ── receive side ──────────────────────────────────────────────────────
	recvMu    sync.Mutex
	expectSeq uint32        // next in-order seq expected (starts at 1)
	ooo       uint64        // SACK bitmap: bit i = received seq expectSeq+i+1
	oooFrames [reliableOOOWindow]*Frame
	ackDirty  bool
	ackTimer  *time.Timer
}

func newReliableState(ch *Channel, cfg ReliableCfg) *reliableState {
	cfg = cfg.withDefaults()
	rs := &reliableState{
		cfg:        cfg,
		channel:    ch,
		nextSeq:    1,
		expectSeq:  1,
		peerWindow: cfg.WindowSize,
		rto:        cfg.BaseRTO,
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
// It blocks when the send window is full (flow control) and returns
// ErrConnClosed if the channel or connection closes while waiting.
// The caller must call sess.send(frame) after preSend returns nil.
func (rs *reliableState) preSend(frame *Frame) error {
	rs.sendMu.Lock()
	for rs.numPending >= rs.peerWindow {
		// Window full: block until the receiver ACKs frames and frees space.
		// cond.Wait atomically releases sendMu and suspends this goroutine.
		dbg("reliable: send window full, waiting for ACK",
			"channel_id", rs.channel.id,
			"num_pending", rs.numPending,
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
		if rs.ackTimer != nil {
			rs.ackTimer.Stop()
			rs.ackTimer = nil
		}
	}
	rs.recvMu.Unlock()

	slot := &rs.pending[seq&0xFF]
	slot.seq = seq
	slot.frame = frame
	slot.sentAt = time.Now()
	slot.retries = 0
	slot.used = true
	rs.numPending++

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

	freed := 0

	// Free all frames with seq < ackSeq (cumulative ACK).
	// AckSeq == expectSeq on the receiver, meaning "next expected is AckSeq",
	// so all seq < AckSeq have been received in-order.
	for s := rs.nextSeq - uint32(rs.numPending); s != rs.nextSeq; s++ {
		slot := &rs.pending[s&0xFF]
		if !slot.used || slot.seq >= ackSeq {
			break
		}
		slot.used = false
		slot.frame = nil
		freed++
	}

	// Free SACK-indicated frames (selective ACK beyond cumulative).
	if bitmap != 0 {
		for i := 0; i < reliableOOOWindow; i++ {
			if bitmap&(1<<uint(i)) != 0 {
				sackSeq := ackSeq + uint32(i) + 1
				slot := &rs.pending[sackSeq&0xFF]
				if slot.used && slot.seq == sackSeq {
					slot.used = false
					slot.frame = nil
					freed++
				}
			}
		}
	}

	rs.numPending -= freed
	if peerWindow > 0 {
		w := int(peerWindow)
		if w > rs.cfg.WindowSize {
			w = rs.cfg.WindowSize
		}
		rs.peerWindow = w
	}
	if freed > 0 {
		dbg("reliable: ACK freed frames",
			"channel_id",  rs.channel.id,
			"freed",       freed,
			"cum_ack_seq", ackSeq,
			"num_pending", rs.numPending,
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
			}
			rs.rtoTimer = time.AfterFunc(rs.rto, rs.retransmit)
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

	rs.rtoTimer = time.AfterFunc(rs.rto, rs.retransmit)
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
			idx := (gap - 1) % reliableOOOWindow
			if rs.oooFrames[idx] == nil {
				rs.oooFrames[idx] = f
				rs.ooo |= 1 << (gap - 1)
				dbg("reliable: buffering out-of-order frame",
					"channel_id", rs.channel.id,
					"seq",        seq,
					"expected",   rs.expectSeq,
					"gap",        gap,
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

	// Drain any buffered OOO frames that are now in order.
	for rs.ooo&1 != 0 {
		next := rs.oooFrames[0]
		// Rotate the OOO window: shift everything down by one slot.
		copy(rs.oooFrames[:], rs.oooFrames[1:])
		rs.oooFrames[reliableOOOWindow-1] = nil
		rs.ooo >>= 1

		if next != nil {
			rs.expectSeq++
			for _, e := range next.Events {
				if e.Type == channelCloseType {
					rs.channel.closeLocal()
				} else {
					deliverEventToChannel(rs.channel, e)
				}
			}
		}
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

// consumePendingACK reads and clears any pending ACK state for piggybacking.
// Returns (cumAck, bitmap, window, true) if an ACK is pending, or (0,0,0,false).
// Must NOT be called with recvMu held.
func (rs *reliableState) consumePendingACK() (cumAck uint32, bitmap uint64, window uint32, ok bool) {
	rs.recvMu.Lock()
	defer rs.recvMu.Unlock()
	if !rs.ackDirty {
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
