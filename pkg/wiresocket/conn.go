package wiresocket

import (
	"context"
	"errors"
	"time"

	"example.com/pulse/pulse/pkg/wiresocket/proto"
)

// ErrConnClosed is returned when an operation is performed on a closed Conn.
var ErrConnClosed = errors.New("wiresocket: connection closed")

// Conn is a bidirectional encrypted event-stream connection.
//
// It wraps an established session and provides a WebSocket-style API:
// send events in one direction, receive them in the other.  A single Conn
// may safely be used from multiple goroutines simultaneously.
type Conn struct {
	sess *session
}

// newConn creates a Conn over an already-established session.
func newConn(s *session) *Conn {
	return &Conn{sess: s}
}

// Send sends one event to the remote peer.
//
// If ctx is cancelled before the send completes the method returns ctx.Err().
// The underlying transport batches the event into a Frame; future versions may
// coalesce multiple concurrent Send calls into a single datagram.
func (c *Conn) Send(ctx context.Context, e *proto.Event) error {
	select {
	case <-c.sess.done:
		return ErrConnClosed
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	if e.TimestampUs == 0 {
		e.TimestampUs = time.Now().UnixMicro()
	}
	return c.sess.send(&proto.Frame{Events: []*proto.Event{e}})
}

// SendFrame sends all events in frame as a single encrypted datagram.
// This is more efficient than calling Send once per event when you have
// multiple events to deliver atomically.
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

// Recv blocks until an event arrives, ctx is cancelled, or the connection is
// closed.
func (c *Conn) Recv(ctx context.Context) (*proto.Event, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.sess.done:
		return nil, ErrConnClosed
	case e, ok := <-c.sess.events:
		if !ok {
			return nil, ErrConnClosed
		}
		return e, nil
	}
}

// Events returns the underlying read-only channel of incoming events.
//
// Prefer Recv for most use-cases; Events is provided for select-loop
// integration where the caller drives its own multiplex logic.
func (c *Conn) Events() <-chan *proto.Event {
	return c.sess.events
}

// Done returns a channel that is closed when the connection terminates.
func (c *Conn) Done() <-chan struct{} {
	return c.sess.done
}

// Close closes the connection.  A disconnect notification is sent to the remote
// peer so it can evict the session immediately.  Subsequent Send and Recv calls
// will return ErrConnClosed.  Close is idempotent.
func (c *Conn) Close() error {
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
