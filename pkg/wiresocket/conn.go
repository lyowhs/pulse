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
	channels sync.Map // uint8 → *Channel
	ch0      *Channel

	// coalescer batches outgoing events; nil when coalescing is disabled.
	coalescer *coalescer

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
}

// newConn creates a non-persistent Conn over an already-established session.
// coalesceInterval > 0 enables the event coalescer.
// wireSession is called here so the router is in place before the caller
// starts the read-loop goroutine.
func newConn(s *session, coalesceInterval time.Duration) *Conn {
	c := &Conn{
		sess: s,
		done: s.done, // alias: done when the session closes
	}
	c.ch0 = newChannel(0, c, s.eventBuf)
	c.channels.Store(uint8(0), c.ch0)
	if coalesceInterval > 0 {
		c.coalescer = newCoalescer(c, coalesceInterval, s.maxFragPayload)
	}
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
	sess.router = func(channelId uint8, e *Event) {
		if e.Type == channelCloseType {
			dbg("conn: channel close from peer", "channel_id", channelId)
			if v, ok := c.channels.LoadAndDelete(channelId); ok {
				v.(*Channel).closeLocal()
			}
			return
		}
		ch := c.getOrOpenChannel(channelId)
		// Deliver to the channel's buffer; drop oldest on overflow.
		select {
		case ch.events <- e:
		default:
			dbg("conn: channel buffer full, dropping oldest", "channel_id", channelId)
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
	// For non-persistent conns, close all channels when the session tears down.
	if !c.isPersistent() {
		sess.onClose = func() {
			c.channels.Range(func(k, v any) bool {
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
		c.channels.Range(func(k, v any) bool {
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
// already exist.
func (c *Conn) getOrOpenChannel(id uint8) *Channel {
	if v, ok := c.channels.Load(id); ok {
		return v.(*Channel)
	}
	ch := newChannel(id, c, cap(c.ch0.events))
	v, loaded := c.channels.LoadOrStore(id, ch)
	if loaded {
		dbg("mux: channel already created by racing goroutine", "channel_id", id)
	}
	return v.(*Channel)
}

// Channel returns the logical channel with the given id, creating it if it
// does not already exist.  Channel 0 is the default channel shared with Send
// and Recv.
func (c *Conn) Channel(id uint8) *Channel {
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
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.done:
		return nil, ErrConnClosed
	case <-c.ch0.done:
		return nil, ErrConnClosed
	case e := <-c.ch0.events:
		return e, nil
	}
}

// Events returns the underlying read-only channel of incoming events on
// channel 0.
func (c *Conn) Events() <-chan *Event {
	return c.ch0.events
}

// Done returns a channel that is closed when the Conn is permanently finished.
// For persistent connections this only fires after Close() is called and the
// reconnect loop has exited.
func (c *Conn) Done() <-chan struct{} {
	return c.done
}

// Close closes the connection.  For persistent connections it stops the
// reconnect loop and waits for it to exit.  Close is idempotent.
func (c *Conn) Close() error {
	if c.isPersistent() {
		dbg("persistent conn close", "addr", c.addr)
		c.cancel()
		<-c.done
		return nil
	}
	dbg("conn close", "local_index", c.sess.localIndex, "remote_addr", c.sess.remoteAddr.String())
	_ = c.sess.sendDisconnect()
	c.sess.close()
	return nil
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
