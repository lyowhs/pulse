package wiresocket

import (
	"context"
	"errors"
	"sync"

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
// uint8 ID.  Channel 0 is the default channel, shared with Conn.Send and
// Conn.Recv.  All other IDs are free for the application to use.
//
// For persistent Conns, Send and Recv block transparently while the underlying
// connection is being re-established.
//
// A Channel may safely be used from multiple goroutines simultaneously.
type Channel struct {
	id        uint8
	conn      *Conn
	events    chan *Event
	done      chan struct{}
	closeOnce sync.Once
}

func newChannel(id uint8, conn *Conn, bufSize int) *Channel {
	dbg("channel opened", "channel_id", id, "buf_size", bufSize)
	return &Channel{
		id:     id,
		conn:   conn,
		events: make(chan *Event, bufSize),
		done:   make(chan struct{}),
	}
}

// ID returns this channel's identifier.
func (ch *Channel) ID() uint8 { return ch.id }

// Send sends an event on this channel to the remote peer.
//
// For persistent conns, if the connection is currently down, Send blocks until
// it is restored.  If ctx is cancelled before the send completes, ctx.Err()
// is returned.
func (ch *Channel) Send(ctx context.Context, e *Event) error {
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
		dbg("channel send", "channel_id", ch.id, "event_type", e.Type)
		err = sess.send(&Frame{ChannelId: ch.id, Events: []*Event{e}})
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
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-ch.conn.done:
		return nil, ErrConnClosed
	case <-ch.done:
		return nil, ErrChannelClosed
	case e := <-ch.events:
		return e, nil
	}
}

// Events returns the read-only channel of incoming events on this channel.
//
// Prefer Recv for most use-cases; Events is provided for select-loop
// integration where the caller drives its own multiplex logic.
func (ch *Channel) Events() <-chan *Event { return ch.events }

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

// closeLocal closes the channel without sending a notification to the peer.
// Used by the mux goroutine when a close event is received, or when the
// session itself terminates.
func (ch *Channel) closeLocal() {
	ch.closeOnce.Do(func() {
		dbg("channel closed", "channel_id", ch.id)
		close(ch.done)
	})
}
