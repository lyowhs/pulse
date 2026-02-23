package wiresocket

import (
	"context"
	"errors"
	"sync"
	"time"

	"example.com/pulse/pulse/pkg/wiresocket/proto"
)

// ErrChannelClosed is returned when an operation is performed on a closed Channel.
var ErrChannelClosed = errors.New("wiresocket: channel closed")

// channelCloseType is the internal event type used to signal channel closure to
// the remote peer.  It is intercepted by the mux goroutine and never delivered
// to application code.
const channelCloseType = "$wiresocket/channel.close"

// Channel is a logical multiplexed stream within a Conn.
//
// Multiple Channels can be opened over a single Conn, each identified by a
// uint32 ID.  Channel 0 is the default channel, shared with Conn.Send and
// Conn.Recv.  All other IDs are free for the application to use.
//
// A Channel may safely be used from multiple goroutines simultaneously.
type Channel struct {
	id        uint32
	conn      *Conn
	events    chan *proto.Event
	done      chan struct{}
	closeOnce sync.Once
}

func newChannel(id uint32, conn *Conn, bufSize int) *Channel {
	dbg("channel opened", "channel_id", id, "buf_size", bufSize)
	return &Channel{
		id:     id,
		conn:   conn,
		events: make(chan *proto.Event, bufSize),
		done:   make(chan struct{}),
	}
}

// ID returns this channel's identifier.
func (ch *Channel) ID() uint32 { return ch.id }

// Send sends an event on this channel to the remote peer.
//
// The event's ChannelId is set to this channel's ID before sending.
// If ctx is cancelled before the send completes, ctx.Err() is returned.
func (ch *Channel) Send(ctx context.Context, e *proto.Event) error {
	select {
	case <-ch.done:
		return ErrChannelClosed
	case <-ch.conn.sess.done:
		return ErrConnClosed
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	e.ChannelId = ch.id
	if e.TimestampUs == 0 {
		e.TimestampUs = time.Now().UnixMicro()
	}
	dbg("channel send", "channel_id", ch.id, "event_type", e.Type, "seq", e.Sequence)
	return ch.conn.sess.send(&proto.Frame{Events: []*proto.Event{e}})
}

// Recv blocks until an event arrives on this channel, ctx is cancelled, or
// the channel or underlying connection is closed.
func (ch *Channel) Recv(ctx context.Context) (*proto.Event, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-ch.conn.sess.done:
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
func (ch *Channel) Events() <-chan *proto.Event { return ch.events }

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
	_ = ch.conn.sess.send(&proto.Frame{
		Events: []*proto.Event{{
			ChannelId: ch.id,
			Type:      channelCloseType,
		}},
	})
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
