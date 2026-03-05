package wiresocket

import (
	"context"
	"sync/atomic"
	"time"
)

// coalesceInputBuf is the number of events buffered in the coalescer's input
// channel.  Deep enough to absorb bursts without back-pressure.
const coalesceInputBuf = 4096

// coalescer batches outgoing events across all channels of a Conn and flushes
// them as single encrypted frames via sess.send.
//
// Channel.Send pushes events into the input channel and returns immediately.
// The goroutine started by newCoalescer drains the input, accumulates events
// per channel in a map, and flushes after the configured interval elapses (or
// when conn.done closes).  Because a Frame carries only one ChannelId, each
// channel's events are sent as a separate frame per flush cycle.
//
// On send error the pending events are dropped; the session or connection
// teardown will surface the error to callers through conn.done / ch.done.
type coalescer struct {
	conn     *Conn
	interval time.Duration
	input    chan coalesceItem
	// maxFrameBytes is the per-channel byte threshold for an immediate flush,
	// set to the session's maxFragPayload so that a single coalesced frame
	// fits in one fragment and avoids triggering excessive fragmentation.
	// 0 means unbounded (flush on timer only).
	maxFrameBytes int
	// stopC carries a response channel from Close() to the run loop.
	// Sending to stopC requests a synchronous flush-and-stop; the run loop
	// closes the response channel when the flush is complete.
	stopC chan chan struct{}
	// stopped is set to true once the run goroutine has exited, making
	// subsequent stop() calls return immediately without blocking.
	stopped atomic.Bool
}

type coalesceItem struct {
	channelId uint8
	event     *Event
}

func newCoalescer(conn *Conn, interval time.Duration, maxFrameBytes int) *coalescer {
	c := &coalescer{
		conn:          conn,
		interval:      interval,
		input:         make(chan coalesceItem, coalesceInputBuf),
		maxFrameBytes: maxFrameBytes,
		stopC:         make(chan chan struct{}, 1),
	}
	go c.run()
	return c
}

// stop requests a synchronous flush of all pending events and waits until
// the coalescer goroutine has finished sending them.  After stop returns,
// the coalescer goroutine has exited and no further events will be sent.
//
// stop is safe to call multiple times; subsequent calls are no-ops.
// If ctx expires before the flush completes, stop returns early (the
// coalescer goroutine continues running until conn.done closes it).
func (c *coalescer) stop(ctx context.Context) {
	if c.stopped.Load() {
		return // already flushed and stopped
	}
	resp := make(chan struct{})
	select {
	case c.stopC <- resp:
		// Sent; wait for acknowledgement.
		select {
		case <-resp:
		case <-ctx.Done():
		}
	case <-ctx.Done():
	case <-c.conn.done:
		// The connection is already down; the run loop flushed on conn.done.
	}
}

// push enqueues an event for coalesced delivery.  It blocks only when the
// input buffer is full (natural back-pressure).
func (c *coalescer) push(ctx context.Context, channelId uint8, e *Event) error {
	select {
	case c.input <- coalesceItem{channelId: channelId, event: e}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-c.conn.done:
		return ErrConnClosed
	}
}

func (c *coalescer) run() {
	pending := make(map[uint8][]*Event)
	pendingBytes := make(map[uint8]int)
	var timer *time.Timer
	var timerC <-chan time.Time

	stopTimer := func() {
		if timer != nil && !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timerC = nil
	}

	// sendFrame sends a frame, routing through the reliable path when applicable.
	sendFrame := func(sess *session, chId uint8, events []*Event) {
		frame := &Frame{ChannelId: chId, Events: events}
		if ch := c.conn.channels[chId].Load(); ch != nil {
			if rs := ch.reliable.Load(); rs != nil {
				if err := rs.preSend(frame); err != nil {
					dbg("coalescer: reliable preSend failed, dropping events",
						"channel_id", chId, "count", len(events), "err", err)
					return
				}
			}
		}
		if err := sess.send(frame); err != nil {
			dbg("coalescer: send failed, dropping events",
				"channel_id", chId, "count", len(events), "err", err)
		}
	}

	// flushAll sends all pending channels and clears the maps.
	flushAll := func(sess *session) {
		for chId, events := range pending {
			sendFrame(sess, chId, events)
			delete(pending, chId)
			delete(pendingBytes, chId)
		}
	}

	// flushOne sends and clears a single channel's pending events.
	flushOne := func(sess *session, chId uint8) {
		if events := pending[chId]; len(events) > 0 {
			sendFrame(sess, chId, events)
			delete(pending, chId)
			delete(pendingBytes, chId)
		}
	}

	getSession := func() *session {
		// currentSession blocks for persistent conns while reconnecting and
		// returns ErrConnClosed when conn.done is closed.
		sess, err := c.conn.currentSession(context.Background())
		if err != nil {
			for k := range pending {
				delete(pending, k)
				delete(pendingBytes, k)
			}
			return nil
		}
		return sess
	}

	addItem := func(item coalesceItem) (fullChannelId uint8, full bool) {
		chId := item.channelId
		pending[chId] = append(pending[chId], item.event)
		if c.maxFrameBytes > 0 {
			pendingBytes[chId] += len(item.event.Payload)
			if pendingBytes[chId] >= c.maxFrameBytes {
				return chId, true
			}
		}
		return 0, false
	}

	for {
		select {
		case resp := <-c.stopC:
			// Graceful-drain request from Close(): flush all pending events,
			// including any items that arrived in the input buffer since the
			// last flush cycle, then signal completion.
			//
			// Items are processed one at a time and flushed immediately when a
			// channel's size limit is reached — the same policy as the normal
			// run path.  This prevents accumulating thousands of events into a
			// single oversized frame that can never fit in the reliable send
			// window, which would cause preSend to block indefinitely.
			stopTimer()
			sess := getSession()
			for len(c.input) > 0 {
				fullCh, full := addItem(<-c.input)
				if full && sess != nil {
					flushOne(sess, fullCh)
				}
			}
			if sess != nil {
				flushAll(sess)
			}
			c.stopped.Store(true)
			close(resp)
			return

		case <-c.conn.done:
			if sess := getSession(); sess != nil {
				stopTimer()
				flushAll(sess)
			}
			c.stopped.Store(true)
			return

		case item := <-c.input:
			fullCh, full := addItem(item)
			// Drain any immediately-available items without blocking so that
			// concurrent senders are coalesced into the same flush cycle.
			// Stop as soon as a channel hits maxFrameBytes so that pending
			// is bounded to at most one packet's worth of data — preventing
			// the drain loop from accumulating thousands of events into a
			// single oversized frame that overflows receiver channel buffers.
			if !full {
			drain:
				for {
					select {
					case item := <-c.input:
						if ch, f := addItem(item); f {
							fullCh = ch
							full = true
							break drain
						}
					default:
						break drain
					}
				}
			}
			if full {
				// At least one channel has reached the frame-size limit.
				// Flush immediately rather than waiting for the timer.
				if sess := getSession(); sess != nil {
					dbg("coalescer: size-limit flush", "channel_id", fullCh, "channels", len(pending))
					if len(pending) == 1 {
						// Fast path: only one channel pending.
						flushOne(sess, fullCh)
					} else {
						flushAll(sess)
					}
				}
				stopTimer()
			} else if timerC == nil {
				// Arm the one-shot flush timer on the first item of a new batch.
				if timer == nil {
					timer = time.NewTimer(c.interval)
				} else {
					timer.Reset(c.interval)
				}
				timerC = timer.C
			}

		case <-timerC:
			timerC = nil
			dbg("coalescer: timer flush", "channels", len(pending))
			if sess := getSession(); sess != nil {
				flushAll(sess)
			}
		}
	}
}
