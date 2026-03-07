package wiresocket

import (
	"context"
	"errors"
	"sync"
	"time"
)

// ErrConnClosed is returned when an operation is performed on a closed Conn.
var ErrConnClosed = errors.New("wiresocket: connection closed")

// Conn is a bidirectional encrypted event-stream connection with channel
// multiplexing.
//
// Multiple logical Channels can be opened over a single Conn via Channel(id).
// Channel 0 is the default, used by Send and Recv.  All channel IDs are
// created on demand and persist until explicitly closed or the connection ends.
//
// If Conn was created with a non-zero ReconnectMin in DialConfig it reconnects
// automatically after a connection loss.  Channel Send and Recv calls block
// transparently while reconnecting.
//
// A Conn may safely be used from multiple goroutines simultaneously.
type Conn struct {
	// channelMap stores open channels keyed by their uint16 ID.
	// sync.Map is used so that per-Conn memory scales with the number of
	// actually-opened channels rather than the full ID space (65535 entries ×
	// 16 B = 1 MB would be too heavy per connection).
	channelMap sync.Map // uint16 → *Channel
	ch0        *Channel // fast path for channel 0 (Send/Recv)

	// coalescer batches outgoing events; nil when coalescing is disabled.
	coalescer *coalescer

	// ackBatcher sends deferred standalone ACKs for all reliable channels,
	// replacing per-channel time.AfterFunc timers (item 6 optimization).
	ackBatcher *ackBatcher

	// mu protects sess and ready for persistent conns; unused for non-persistent.
	mu   sync.RWMutex
	sess *session // current session; immutable for non-persistent

	// Persistent-only fields (zero/nil for non-persistent).
	addr    string
	dialCfg DialConfig
	ready   chan struct{} // closed when sess is valid; replaced on each disconnect
	ctx     context.Context
	cancel  context.CancelFunc

	// done is closed when the Conn is permanently finished:
	//  - non-persistent: aliased to sess.done (closed when the session ends)
	//  - persistent: closed when reconnectLoop exits after Close()
	done chan struct{}

	// cc is non-nil when CongestionControl is configured.  It persists across
	// session reconnects so that the learned rate (ssthresh) is preserved.
	cc *aimdController

	// newChannelCfg is the ReliableCfg applied when a new channel is created.
	// Zero value gives library defaults (defaultReliableWindow, defaultBaseRTO,
	// etc.).  Set MaxRetries = 30 when CongestionControl is configured so that
	// rate-limited sends do not time out at the default MaxRetries of 10.
	newChannelCfg ReliableCfg
}

// InflightCap returns the maximum number of events that can be in-flight
// simultaneously on this connection without overflowing the socket receive
// buffer.  This equals the EventBufSize computed (or provided) at dial time
// and is the natural bound for application-level send semaphores and RTT
// measurement ring buffers.
func (c *Conn) InflightCap() int {
	return c.newChannelCfg.WindowSize
}

// CongestionRateKBps returns the current AIMD congestion-controller send rate
// in KiB/s, or 0 if congestion control is not configured on this Conn.
func (c *Conn) CongestionRateKBps() float64 {
	if c.cc == nil {
		return 0
	}
	return c.cc.currentRateKBps()
}

// newConn creates a non-persistent Conn over an already-established session.
// coalesceInterval > 0 enables the event coalescer.
// wireSession is called here so the router is in place before the caller
// starts the read-loop goroutine.
func newConn(s *session, coalesceInterval time.Duration, newChannelCfg ReliableCfg) *Conn {
	c := &Conn{
		sess:          s,
		done:          s.done, // alias: done when the session closes
		newChannelCfg: newChannelCfg,
	}
	c.ch0 = newChannel(0, c, s.eventBuf)
	c.channelMap.Store(uint16(0), c.ch0)
	if coalesceInterval > 0 {
		c.coalescer = newCoalescer(c, coalesceInterval, s.maxFragPayload)
	}
	c.ackBatcher = newAckBatcher(c)
	c.wireSession(s)
	dbg("conn created", "local_index", s.localIndex, "remote_addr", s.remoteAddr.String())
	return c
}

// isPersistent reports whether this Conn reconnects automatically.
func (c *Conn) isPersistent() bool { return c.cancel != nil }

// sessionFast returns the current session without blocking.
// For non-persistent conns, always returns the fixed session.
// For persistent conns, returns nil while disconnected.
func (c *Conn) sessionFast() *session {
	if !c.isPersistent() {
		return c.sess
	}
	c.mu.RLock()
	s := c.sess
	c.mu.RUnlock()
	return s
}

// currentSession returns the active session, blocking for persistent conns
// until one is available, ctx is cancelled, or the Conn is closed.
func (c *Conn) currentSession(ctx context.Context) (*session, error) {
	if !c.isPersistent() {
		return c.sess, nil
	}
	for {
		c.mu.RLock()
		sess := c.sess
		ready := c.ready
		c.mu.RUnlock()

		if sess != nil {
			return sess, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-c.done:
			return nil, ErrConnClosed
		case <-ready:
			// Connection re-established; re-read under lock.
		}
	}
}

// wireSession installs the event router and optional teardown callback on sess.
// It must be called before the goroutine that drives sess (clientReadLoop or
// a server worker) is started; goroutine-start is a happens-before boundary
// in the Go memory model, so no extra synchronisation is needed for visibility
// of sess.router inside the read-loop goroutine.
func (c *Conn) wireSession(sess *session) {
	// If a congestion controller is configured, wire it into the new session as
	// the rate limiter and re-baseline the retransmit counter so that the
	// reliable-state reset on reconnect is not misread as a loss event.
	if c.cc != nil {
		sess.rateLimiter = c.cc
		c.cc.onReconnect()
	}

	sess.router = func(f *Frame) {
		ch := c.getOrOpenChannel(f.ChannelId)

		// Process any piggybacked or standalone ACK.
		if f.AckSeq != 0 {
			if rs := ch.reliable.Load(); rs != nil {
				rs.onAck(f.AckSeq, f.AckBitmap, f.WindowSize)
			}
		}

		// Reliable data frame.
		if f.Seq != 0 {
			rs := ch.reliable.Load()
			if rs == nil {
				// Auto-create receive-side state for channels that did not
				// call SetReliable but are receiving reliable frames.
				// Use CAS to prevent duplicate creation from concurrent workers.
				rs = newAutoReliable(ch)
				if !ch.reliable.CompareAndSwap(nil, rs) {
					// Another worker won the race; use its state.
					rs = ch.reliable.Load()
				}
			}
			rs.onRecv(f.Seq, f)
			return
		}

		// Unreliable frame: deliver events directly.
		for _, e := range f.Events {
			if e.Type == channelCloseType {
				dbg("conn: channel close from peer", "channel_id", f.ChannelId)
				if v, ok := c.channelMap.LoadAndDelete(f.ChannelId); ok {
					v.(*Channel).closeLocal()
				}
				return
			}
			// Deliver to the channel's ring; drop newest on overflow.
			if !ch.ring.push(e) {
				dbg("conn: channel buffer full, dropping event", "channel_id", f.ChannelId)
				DebugRingDropped.Add(1)
			} else {
				DebugEventsDelivered.Add(1)
			}
		}
	}

	// Reset reliable state on all open channels when a new session is wired.
	// For persistent conns this fires on every reconnect, purging unACKed frames
	// from the old session (which is now dead) and waking blocked senders.
	c.channelMap.Range(func(_, v any) bool {
		ch := v.(*Channel)
		if rs := ch.reliable.Load(); rs != nil {
			dbg("conn: resetting reliable channel state on reconnect", "channel_id", ch.id)
			rs.reset()
		}
		return true
	})

	// For non-persistent conns, close all channels when the session tears down.
	if !c.isPersistent() {
		sess.onClose = func() {
			c.channelMap.Range(func(_, v any) bool {
				v.(*Channel).closeLocal()
				return true
			})
		}
	}
}

// reconnectLoop watches the current session for termination and reconnects.
// It runs for the lifetime of a persistent Conn.
func (c *Conn) reconnectLoop() {
	defer func() {
		// Permanently closed: shut down all channels.
		c.channelMap.Range(func(_, v any) bool {
			v.(*Channel).closeLocal()
			return true
		})
		close(c.done)
	}()

	for {
		c.mu.RLock()
		sess := c.sess
		c.mu.RUnlock()

		select {
		case <-c.ctx.Done():
			if sess != nil {
				_ = sess.sendDisconnect()
				sess.close()
			}
			return
		case <-sess.done:
		}

		dbg("persistent: connection lost", "addr", c.addr)

		c.mu.Lock()
		c.sess = nil
		c.ready = make(chan struct{})
		c.mu.Unlock()

		// For reconnect attempts, make a single handshake attempt per
		// outer iteration — the outer backoff owns all retry spacing.
		reconnectCfg := c.dialCfg
		reconnectCfg.MaxRetries = 1

		backoff := c.dialCfg.ReconnectMin
		for {
			select {
			case <-c.ctx.Done():
				dbg("persistent: reconnect loop stopped", "addr", c.addr)
				return
			case <-time.After(backoff):
			}

			dbg("persistent: attempting reconnect", "addr", c.addr, "backoff", backoff)
			raddr, udpConn, newSess, err := dialSession(c.ctx, c.addr, reconnectCfg)
			if err != nil {
				dbg("persistent: reconnect failed", "addr", c.addr, "err", err)
				backoff *= 2
				if backoff > c.dialCfg.ReconnectMax {
					backoff = c.dialCfg.ReconnectMax
				}
				continue
			}

			dbg("persistent: reconnected", "addr", c.addr)
			// Wire the router before starting the read loop so the happens-before
			// boundary ensures sess.router is visible inside the goroutine.
			c.wireSession(newSess)
			go clientReadLoop(udpConn, newSess, raddr)
			go clientKeepaliveLoop(newSess)

			c.mu.Lock()
			c.sess = newSess
			close(c.ready)
			c.mu.Unlock()
			break
		}
	}
}

// getOrOpenChannel returns the Channel for id, creating it if it does not
// already exist.  Channel 0 is returned directly via the ch0 fast path.
func (c *Conn) getOrOpenChannel(id uint16) *Channel {
	if id == 0 {
		return c.ch0 // fast path for the default channel
	}
	if v, ok := c.channelMap.Load(id); ok {
		return v.(*Channel)
	}
	ch := newChannel(id, c, c.ch0.ring.Cap())
	// LoadOrStore is race-safe: only one goroutine wins; the rest use the winner.
	actual, loaded := c.channelMap.LoadOrStore(id, ch)
	if loaded {
		dbg("mux: channel already created by racing goroutine", "channel_id", id)
		return actual.(*Channel)
	}
	return ch
}

// Channel returns the logical channel with the given id, creating it if it
// does not already exist.  Channel 0 is the default channel shared with Send
// and Recv.  Valid IDs are 0–65534; ID 65535 is reserved for internal use.
func (c *Conn) Channel(id uint16) *Channel {
	return c.getOrOpenChannel(id)
}

// Send sends one event to the remote peer on channel 0.
//
// For persistent conns, if the connection is currently down, Send blocks until
// it is restored.  If ctx is cancelled the method returns ctx.Err().
// When coalescing is enabled, Send returns as soon as the event is queued.
func (c *Conn) Send(ctx context.Context, e *Event) error {
	return c.ch0.Send(ctx, e)
}

// SendFrame sends all events in frame as a single encrypted datagram.
func (c *Conn) SendFrame(ctx context.Context, frame *Frame) error {
	for {
		select {
		case <-c.done:
			return ErrConnClosed
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		sess, err := c.currentSession(ctx)
		if err != nil {
			return err
		}
		err = sess.send(frame)
		if err == ErrConnClosed && c.isPersistent() {
			continue
		}
		return err
	}
}

// Recv blocks until an event arrives on channel 0, ctx is cancelled, or the
// connection is closed.
func (c *Conn) Recv(ctx context.Context) (*Event, error) {
	return c.ch0.Recv(ctx)
}

// Events returns the signal channel for channel 0's receive buffer.
// See Channel.Events for details.
func (c *Conn) Events() <-chan struct{} {
	return c.ch0.Events()
}

// PopEvent removes and returns one event from channel 0's receive buffer
// without blocking.  Returns (nil, false) if the buffer is empty.
// See Channel.PopEvent for details.
func (c *Conn) PopEvent() (*Event, bool) {
	return c.ch0.PopEvent()
}

// Done returns a channel that is closed when the Conn is permanently finished.
// For persistent connections this only fires after Close() is called and the
// reconnect loop has exited.
func (c *Conn) Done() <-chan struct{} {
	return c.done
}

// defaultDrainTimeout is the maximum time Close spends flushing coalesced
// events and waiting for reliable-channel ACKs before tearing down the session.
const defaultDrainTimeout = 5 * time.Second

// Flush flushes any events buffered in the coalescer, sending them to the
// remote peer immediately.  Unlike Close, Flush does not send a disconnect or
// tear down the session — the connection remains open for further sends and
// receives after Flush returns.
//
// For reliable channels, Flush also blocks until all outstanding sent frames
// have been ACKed by the remote peer (same guarantee as Close).
//
// Flush is useful when a caller needs to ensure all queued events have left
// the local buffer before inspecting delivery metrics, while still keeping
// the connection alive.  Bounded by ctx; partial flushes are silently
// tolerated.
func (c *Conn) Flush(ctx context.Context) {
	// Step 1: flush the coalescer without stopping it so further sends work.
	if c.coalescer != nil {
		c.coalescer.flush(ctx)
	}
	// Step 2: wait for every reliable channel's send window to empty.
	c.channelMap.Range(func(_, v any) bool {
		if ctx.Err() != nil {
			return false
		}
		if rs := v.(*Channel).reliable.Load(); rs != nil {
			_ = rs.waitEmpty(ctx)
		}
		return true
	})
}

// Close closes the connection.  Before tearing down the session it performs a
// graceful drain:
//
//  1. The coalescer (if enabled) is flushed synchronously so that any events
//     queued but not yet sent are transmitted.
//
//  2. For each reliable channel, Close waits until all outstanding sent frames
//     have been ACKed by the remote peer.
//
// The drain phase is bounded by a 5-second timeout; any data that cannot be
// delivered within that window is abandoned before the disconnect packet is
// sent.
//
// For persistent connections the drain runs against the currently active
// session, then the reconnect loop is stopped.  Close is idempotent.
func (c *Conn) Close() error {
	drainCtx, drainCancel := context.WithTimeout(context.Background(), defaultDrainTimeout)
	defer drainCancel()

	if c.isPersistent() {
		dbg("persistent conn close", "addr", c.addr)
		c.drainBeforeClose(drainCtx)
		c.cancel()
		<-c.done
		return nil
	}

	dbg("conn close", "local_index", c.sess.localIndex, "remote_addr", c.sess.remoteAddr.String())
	c.drainBeforeClose(drainCtx)
	_ = c.sess.sendDisconnect()
	c.sess.close()
	return nil
}

// drainBeforeClose flushes pending coalesced events and waits for reliable
// channels to receive ACKs, all bounded by ctx.
func (c *Conn) drainBeforeClose(ctx context.Context) {
	// Step 1: flush the coalescer so buffered events reach the wire.
	if c.coalescer != nil {
		c.coalescer.stop(ctx)
	}
	// Step 2: wait for every reliable channel's send window to empty.
	c.channelMap.Range(func(_, v any) bool {
		if ctx.Err() != nil {
			return false
		}
		if rs := v.(*Channel).reliable.Load(); rs != nil {
			_ = rs.waitEmpty(ctx)
		}
		return true
	})
}

// RemoteAddr returns the UDP address of the remote peer.
// For persistent connections, returns the configured server address.
func (c *Conn) RemoteAddr() string {
	if c.isPersistent() {
		return c.addr
	}
	return c.sess.remoteAddr.String()
}

// LocalIndex returns this side's current session index.
// Returns 0 if a persistent connection is currently disconnected.
func (c *Conn) LocalIndex() uint32 {
	sess := c.sessionFast()
	if sess == nil {
		return 0
	}
	return sess.localIndex
}
