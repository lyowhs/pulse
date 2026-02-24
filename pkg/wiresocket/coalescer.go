package wiresocket

import (
	"context"
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
	}
	go c.run()
	return c
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

	// flushAll sends all pending channels and clears the maps.
	flushAll := func(sess *session) {
		for chId, events := range pending {
			if err := sess.send(&Frame{ChannelId: chId, Events: events}); err != nil {
				dbg("coalescer: send failed, dropping events",
					"channel_id", chId, "count", len(events), "err", err)
			}
			delete(pending, chId)
			delete(pendingBytes, chId)
		}
	}

	// flushOne sends and clears a single channel's pending events.
	flushOne := func(sess *session, chId uint8) {
		if events := pending[chId]; len(events) > 0 {
			if err := sess.send(&Frame{ChannelId: chId, Events: events}); err != nil {
				dbg("coalescer: send failed, dropping events",
					"channel_id", chId, "count", len(events), "err", err)
			}
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
		case <-c.conn.done:
			if sess := getSession(); sess != nil {
				stopTimer()
				flushAll(sess)
			}
			return

		case item := <-c.input:
			fullCh, full := addItem(item)
			// Drain any immediately-available items without blocking so that
			// concurrent senders are coalesced into the same flush cycle.
		drain:
			for {
				select {
				case item := <-c.input:
					if ch, f := addItem(item); f {
						// Multiple channels may fill; track the last one —
						// flushAll below handles all of them.
						fullCh = ch
						full = true
					}
				default:
					break drain
				}
			}
			if full {
				// At least one channel has reached the frame-size limit.
				// Flush immediately rather than waiting for the timer.
				if sess := getSession(); sess != nil {
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
			if sess := getSession(); sess != nil {
				flushAll(sess)
			}
		}
	}
}
