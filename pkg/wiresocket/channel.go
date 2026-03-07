package wiresocket

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

// ErrChannelClosed is returned when an operation is performed on a closed Channel.
var ErrChannelClosed = errors.New("wiresocket: channel closed")

// channelCloseType is the internal event type used to signal channel closure to
// the remote peer.  It is intercepted by the mux goroutine and never delivered
// to application code.  255 is reserved for wiresocket internal use.
const channelCloseType = uint8(255)

// Channel is a logical multiplexed stream within a Conn.
//
// Multiple Channels can be opened over a single Conn, each identified by a
// uint16 ID (0–65534; 65535 is reserved).  Channel 0 is the default channel,
// shared with Conn.Send and Conn.Recv.  All other IDs are free for the
// application to use.
//
// For persistent Conns, Send and Recv block transparently while the underlying
// connection is being re-established.
//
// A Channel may safely be used from multiple goroutines simultaneously.
type Channel struct {
	id        uint16
	conn      *Conn
	ring      *eventRing // lock-free MPSC event buffer (Item 2)
	done      chan struct{}
	closeOnce sync.Once

	// reliable is non-nil when reliable delivery is enabled on this channel.
	// nil means fire-and-forget (zero overhead on the send/receive hot-paths).
	// Uses atomic.Pointer so the router goroutines (workers) can load it
	// concurrently with SetReliable being called from OnConnect.
	reliable atomic.Pointer[reliableState]
}

func newChannel(id uint16, conn *Conn, bufSize int) *Channel {
	dbg("channel opened", "channel_id", id, "buf_size", bufSize)
	ch := &Channel{
		id:   id,
		conn: conn,
		ring: newEventRing(bufSize),
		done: make(chan struct{}),
	}
	ch.reliable.Store(newReliableState(ch, conn.newChannelCfg))
	return ch
}

// ID returns this channel's identifier.
func (ch *Channel) ID() uint16 { return ch.id }

// SetUnreliable disables reliable delivery on this channel, reverting it to
// fire-and-forget mode.  Any goroutine blocked in Send waiting for window
// space is immediately unblocked with ErrChannelClosed.
//
// SetUnreliable may be called at any time, but should be called before the
// first Send or Recv to avoid a transient reliable window that the peer could
// observe.
func (ch *Channel) SetUnreliable() {
	if old := ch.reliable.Swap(nil); old != nil {
		old.cond.Broadcast() // unblock any goroutine in preSend's cond.Wait
	}
}

// SetReliable enables reliable delivery and window-based flow control on this
// channel.  Channels are reliable by default; call this to change the
// configuration (e.g. window size or retransmit timeout) after creation.
//
// When reliable mode is active:
//   - Each sent frame is assigned a sequence number and buffered until ACKed.
//   - The sender blocks when the peer's receive window is exhausted (flow control).
//   - Lost frames are retransmitted automatically with exponential backoff.
//   - Received frames are delivered in order; out-of-order arrivals are buffered.
//   - ACKs are piggybacked on outgoing data frames; standalone ACK packets are
//     sent after at most cfg.ACKDelay when no data is flowing.
func (ch *Channel) SetReliable(cfg ReliableCfg) {
	rs := newReliableState(ch, cfg)
	// Copy receive-side progress from the existing state so we don't reset
	// expectSeq back to 1 (e.g. when reconfiguring window size mid-stream).
	if old := ch.reliable.Load(); old != nil {
		// Hold old.recvMu across both the state copy AND the Store so that
		// onRecv's re-check (done after acquiring recvMu) can reliably detect
		// the swap.  This guarantees that ackDirty=true set by an onRecv that
		// raced with SetReliable is visible in the new state (because onRecv
		// will either: set ackDirty on old state THEN release the lock, letting
		// SetReliable copy ackDirty=true into the new state; OR onRecv gets the
		// lock AFTER SetReliable releases it, sees the new state via re-check,
		// and forwards to it).
		old.recvMu.Lock()
		rs.expectSeq = old.expectSeq
		rs.ooo = old.ooo
		rs.oooFrames = old.oooFrames
		rs.ackDirty.Store(old.ackDirty.Load())
		ch.reliable.Store(rs)
		old.recvMu.Unlock()
	} else {
		ch.reliable.Store(rs)
	}
}

// Send sends an event on this channel to the remote peer.
//
// For persistent conns, if the connection is currently down, Send blocks until
// it is restored.  If ctx is cancelled before the send completes, ctx.Err()
// is returned.
//
// When coalescing is enabled, Send enqueues the event and returns immediately;
// the coalescer goroutine batches it with other pending events before sending.
//
// When reliable mode is active (SetReliable was called), Send may block until
// the remote peer's receive window has space.
func (ch *Channel) Send(ctx context.Context, e *Event) error {
	// Use the coalescer when it is configured AND the event is small enough
	// that it may be batched with other events.  When a single event fills
	// an entire frame (evtWire + frameHeaderBudget >= maxFrameBytes), the
	// coalescer would flush immediately without batching anything, so we
	// bypass it to avoid 2 extra goroutine context switches per send.
	if c := ch.conn.coalescer; c != nil && !c.fillsPacket(e) {
		select {
		case <-ch.done:
			return ErrChannelClosed
		case <-ch.conn.done:
			return ErrConnClosed
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		dbg("channel send (coalesced)", "channel_id", ch.id, "event_type", e.Type)
		return c.push(ctx, ch.id, e)
	}
	if ch.conn.coalescer != nil {
		dbg("channel send (coalescer bypass: event fills packet)",
			"channel_id", ch.id, "event_type", e.Type, "payload_len", len(e.Payload))
	}
	for {
		select {
		case <-ch.done:
			return ErrChannelClosed
		case <-ch.conn.done:
			return ErrConnClosed
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		sess, err := ch.conn.currentSession(ctx)
		if err != nil {
			return err
		}
		// Pool the Frame + single-element Events slice via singleEventFramePool,
		// eliminating 2 heap allocations per send.  For reliable channels the
		// poolSF is stored in the pending ring slot and returned by onAck/reset;
		// for unreliable channels it is returned immediately after sess.send.
		sf := getSingleEventFrame(ch.id, e)
		frame := &sf.f
		// Capture rs once so the reliable-vs-unreliable decision is consistent
		// throughout this iteration (SetUnreliable could race with us otherwise).
		rs := ch.reliable.Load()
		if rs != nil {
			dbg("channel send (reliable)", "channel_id", ch.id, "event_type", e.Type)
			if err := rs.preSend(frame, sf); err != nil {
				// preSend failed before storing sf in any slot; return it now.
				putSingleEventFrame(sf)
				if err == ErrConnClosed && ch.conn.isPersistent() {
					continue
				}
				return err
			}
			// sf ownership transferred to the pending slot; onAck/reset returns it.
		} else {
			dbg("channel send", "channel_id", ch.id, "event_type", e.Type)
		}
		err = sess.send(frame)
		if rs == nil {
			// Unreliable: frame is done the moment sess.send returns.
			putSingleEventFrame(sf)
		}
		if err == ErrConnClosed && ch.conn.isPersistent() {
			dbg("channel send: connection lost, waiting for reconnect", "channel_id", ch.id)
			continue
		}
		return err
	}
}

// Recv blocks until an event arrives on this channel, ctx is cancelled, or
// the channel or underlying connection is closed.
//
// For persistent conns, Recv blocks transparently during reconnection.
func (ch *Channel) Recv(ctx context.Context) (*Event, error) {
	for {
		// Non-blocking pop first (avoids goroutine scheduling for hot path).
		if e, ok := ch.ring.pop(); ok {
			// After draining an event, proactively send a window-update ACK if
			// our receive window has grown beyond what we last advertised.
			if rs := ch.reliable.Load(); rs != nil {
				rs.notifyWindowIncreased()
			}
			return e, nil
		}
		// Block until a signal arrives, the context expires, or we are closed.
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ch.conn.done:
			return nil, ErrConnClosed
		case <-ch.done:
			// Prefer ErrConnClosed when the conn was also closed (e.g. conn.Close()
			// closes conn.done then calls ch.closeLocal(), so both are closed).
			select {
			case <-ch.conn.done:
				return nil, ErrConnClosed
			default:
				return nil, ErrChannelClosed
			}
		case <-ch.ring.Sig():
			// Retry the pop on the next iteration.
		}
	}
}

// Events returns a signal channel (capacity 1) that receives a struct{}
// whenever at least one event is available in the channel's receive buffer.
// Use PopEvent to retrieve the actual event(s) after receiving the signal.
//
// Prefer Recv for most use-cases; Events is provided for select-loop
// integration where the caller drives its own multiplex logic.
func (ch *Channel) Events() <-chan struct{} { return ch.ring.Sig() }

// PopEvent removes and returns one event from the channel's receive buffer
// without blocking.  Returns (nil, false) if the buffer is empty.
// After a signal on Events(), call PopEvent in a loop until it returns false
// to drain all pending events.
func (ch *Channel) PopEvent() (*Event, bool) {
	e, ok := ch.ring.pop()
	if ok {
		if rs := ch.reliable.Load(); rs != nil {
			rs.notifyWindowIncreased()
		}
	}
	return e, ok
}

// Done returns a channel that is closed when this channel is closed.
func (ch *Channel) Done() <-chan struct{} { return ch.done }

// Close sends a close notification to the remote peer and closes this channel
// locally.  Subsequent Send and Recv calls return ErrChannelClosed.
// Close is idempotent.
func (ch *Channel) Close() error {
	select {
	case <-ch.done:
		return nil // already closed
	default:
	}
	dbg("channel close (local)", "channel_id", ch.id)
	// Notify the peer (best-effort; ignore send errors).
	if sess := ch.conn.sessionFast(); sess != nil {
		_ = sess.send(&Frame{
			ChannelId: ch.id,
			Events:    []*Event{{Type: channelCloseType}},
		})
	}
	ch.closeLocal()
	return nil
}

// NumPending returns the number of sent frames awaiting ACK on this channel.
// Returns 0 if reliable mode is not enabled.
func (ch *Channel) NumPending() int32 {
	rs := ch.reliable.Load()
	if rs == nil {
		return 0
	}
	return rs.numPendingFast.Load()
}

// RingLen returns the number of received events waiting in the channel's
// receive buffer (not yet consumed by Recv/PopEvent).
func (ch *Channel) RingLen() int { return ch.ring.Len() }

// NextSeq returns the next sequence number that will be assigned by preSend.
// (nextSeq - 1) equals the total number of reliable frames sent on this channel.
// Returns 0 if reliable mode is not enabled.
func (ch *Channel) NextSeq() uint32 {
	rs := ch.reliable.Load()
	if rs == nil {
		return 0
	}
	rs.sendMu.Lock()
	seq := rs.nextSeq
	rs.sendMu.Unlock()
	return seq
}

// ExpectSeq returns the next in-order sequence number the receive side expects.
// Returns 0 if reliable mode is not enabled.
func (ch *Channel) ExpectSeq() uint32 {
	rs := ch.reliable.Load()
	if rs == nil {
		return 0
	}
	rs.recvMu.Lock()
	seq := rs.expectSeq
	rs.recvMu.Unlock()
	return seq
}

// Retransmits returns the cumulative number of frame retransmit events on this
// channel since it was created.  Returns 0 if reliable mode is not enabled.
func (ch *Channel) Retransmits() int64 {
	rs := ch.reliable.Load()
	if rs == nil {
		return 0
	}
	return rs.retransmits.Load()
}

// closeLocal closes the channel without sending a notification to the peer.
// Used by the mux goroutine when a close event is received, or when the
// session itself terminates.
func (ch *Channel) closeLocal() {
	ch.closeOnce.Do(func() {
		dbg("channel closed", "channel_id", ch.id)
		close(ch.done)
		// Close the ring so any goroutine blocked in Recv (waiting on ring.Sig)
		// is woken and can observe the done channel.
		ch.ring.close()
		// Wake any goroutine blocked in preSend's cond.Wait so it can
		// detect the channel-closed condition and return ErrChannelClosed.
		if rs := ch.reliable.Load(); rs != nil {
			rs.cond.Broadcast()
		}
	})
}

// recvTimeout blocks for up to timeout waiting for an event.
// Used internally by tests and helpers; not part of the public API.
func (ch *Channel) recvTimeout(timeout time.Duration) (*Event, bool) {
	deadline := time.Now().Add(timeout)
	for {
		if e, ok := ch.ring.pop(); ok {
			return e, true
		}
		rem := time.Until(deadline)
		if rem <= 0 {
			return nil, false
		}
		t := time.NewTimer(rem)
		select {
		case <-ch.ring.Sig():
			t.Stop()
		case <-t.C:
		}
	}
}
