package wiresocket

import (
	"context"
	"errors"
	"sync"

	"example.com/pulse/pulse/pkg/wiresocket/proto"
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
// A Conn may safely be used from multiple goroutines simultaneously.
type Conn struct {
	sess     *session
	channels sync.Map // uint8 → *Channel
	ch0      *Channel // channel 0 — default channel for Send/Recv
}

// newConn creates a Conn over an already-established session and starts the
// internal channel-mux goroutine.
func newConn(s *session) *Conn {
	c := &Conn{sess: s}
	c.ch0 = newChannel(0, c, cap(s.events))
	c.channels.Store(uint8(0), c.ch0)
	dbg("conn created", "local_index", s.localIndex, "remote_addr", s.remoteAddr.String())
	go c.mux()
	return c
}

// mux reads from the session's raw event stream and routes each event to the
// appropriate Channel based on its ChannelID.  It runs for the lifetime of the
// session, and closes all open channels when the session ends.
func (c *Conn) mux() {
	dbg("mux started", "local_index", c.sess.localIndex)
	defer func() {
		dbg("mux stopped, closing all channels", "local_index", c.sess.localIndex)
		c.channels.Range(func(k, v any) bool {
			v.(*Channel).closeLocal()
			return true
		})
	}()
	for {
		select {
		case <-c.sess.done:
			return
		case e, ok := <-c.sess.events:
			if !ok {
				return
			}
			// Intercept channel-close control events — never deliver to app.
			if e.Type == channelCloseType {
				dbg("mux: channel close from peer", "channel_id", e.ChannelId)
				if v, ok := c.channels.LoadAndDelete(e.ChannelId); ok {
					v.(*Channel).closeLocal()
				}
				continue
			}
			ch := c.getOrOpenChannel(e.ChannelId)
			// Deliver to the channel's buffer; drop oldest on overflow.
			select {
			case ch.events <- e:
			default:
				dbg("mux: channel buffer full, dropping oldest", "channel_id", e.ChannelId)
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
	}
}

// getOrOpenChannel returns the Channel for id, creating it if it does not
// already exist.
func (c *Conn) getOrOpenChannel(id uint8) *Channel {
	if v, ok := c.channels.Load(id); ok {
		return v.(*Channel)
	}
	ch := newChannel(id, c, cap(c.sess.events))
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
// If ctx is cancelled before the send completes the method returns ctx.Err().
func (c *Conn) Send(ctx context.Context, e *proto.Event) error {
	select {
	case <-c.sess.done:
		return ErrConnClosed
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	e.ChannelId = 0 // enforce default channel
	return c.sess.send(&proto.Frame{Events: []*proto.Event{e}})
}

// SendFrame sends all events in frame as a single encrypted datagram.
// This is more efficient than calling Send once per event when you have
// multiple events to deliver atomically.  ChannelID on each event is used
// as-is, allowing events for multiple channels to be coalesced into one
// datagram.
func (c *Conn) SendFrame(ctx context.Context, frame *proto.Frame) error {
	select {
	case <-c.sess.done:
		return ErrConnClosed
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	return c.sess.send(frame)
}

// Recv blocks until an event arrives on channel 0, ctx is cancelled, or the
// connection is closed.
func (c *Conn) Recv(ctx context.Context) (*proto.Event, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.sess.done:
		return nil, ErrConnClosed
	case <-c.ch0.done:
		return nil, ErrConnClosed
	case e := <-c.ch0.events:
		return e, nil
	}
}

// Events returns the underlying read-only channel of incoming events on
// channel 0.
//
// Prefer Recv for most use-cases; Events is provided for select-loop
// integration where the caller drives its own multiplex logic.
func (c *Conn) Events() <-chan *proto.Event {
	return c.ch0.events
}

// Done returns a channel that is closed when the connection terminates.
func (c *Conn) Done() <-chan struct{} {
	return c.sess.done
}

// Close closes the connection.  A disconnect notification is sent to the
// remote peer so it can evict the session immediately.  Subsequent Send and
// Recv calls will return ErrConnClosed.  Close is idempotent.
func (c *Conn) Close() error {
	dbg("conn close", "local_index", c.sess.localIndex, "remote_addr", c.sess.remoteAddr.String())
	// Best-effort: ignore send errors (peer may already be gone).
	_ = c.sess.sendDisconnect()
	c.sess.close()
	return nil
}

// RemoteAddr returns the UDP address of the remote peer.
func (c *Conn) RemoteAddr() string {
	return c.sess.remoteAddr.String()
}

// LocalIndex returns this side's session index (the remote peer uses this as
// ReceiverIndex in data packets directed at us).
func (c *Conn) LocalIndex() uint32 {
	return c.sess.localIndex
}
