package wiresocket

import (
	"context"
	"sync/atomic"
	"time"
)

const (
	// coalesceInputBuf is the number of events buffered in the coalescer's input
	// channel.  Deep enough to absorb bursts without back-pressure.
	coalesceInputBuf = 4096

	// frameHeaderBudget is the conservative byte budget reserved for per-frame
	// wire fields: ChannelId(2) + Seq(5) + AckSeq(5) + AckBitmap(9) +
	// WindowSize(5) = 26 bytes actual; 32 for a safety margin.
	// This constant is shared by addItem (flush threshold) and fillsPacket
	// (coalescer-bypass predicate) to guarantee they use identical logic.
	frameHeaderBudget = 32
)

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
	// flushC carries a response channel from flush() to the run loop.
	// Sending to flushC requests a synchronous flush without stopping; the
	// run loop closes the response channel when the flush is complete and
	// then continues running normally.
	flushC chan chan struct{}
	// stopped is set to true once the run goroutine has exited, making
	// subsequent stop() calls return immediately without blocking.
	stopped atomic.Bool
}

type coalesceItem struct {
	channelId uint16
	event     *Event
}

func newCoalescer(conn *Conn, interval time.Duration, maxFrameBytes int) *coalescer {
	c := &coalescer{
		conn:          conn,
		interval:      interval,
		input:         make(chan coalesceItem, coalesceInputBuf),
		maxFrameBytes: maxFrameBytes,
		stopC:         make(chan chan struct{}, 1),
		flushC:        make(chan chan struct{}, 1),
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

// flush requests a synchronous flush of all pending events without stopping
// the coalescer goroutine.  After flush returns the coalescer continues
// running and accepts further events.
//
// flush is safe to call concurrently with push and stop.
// If ctx expires before the flush completes, flush returns early.
func (c *coalescer) flush(ctx context.Context) {
	if c.stopped.Load() {
		return // already stopped; nothing to flush
	}
	resp := make(chan struct{})
	select {
	case c.flushC <- resp:
		// Sent; wait for acknowledgement.
		select {
		case <-resp:
		case <-ctx.Done():
		}
	case <-ctx.Done():
	case <-c.conn.done:
	}
}

// fillsPacket reports whether a single event fills or exceeds the per-frame
// byte budget, making coalescing futile.  When true, Channel.Send bypasses
// the coalescer goroutine entirely, sending the event on the direct path.
// This eliminates 2 goroutine context switches per large-event send.
//
// The predicate mirrors addItem's flush condition: if a single event already
// satisfies the flush threshold, adding it to the coalescer would immediately
// produce a full frame anyway — no other events would be coalesced with it.
func (c *coalescer) fillsPacket(e *Event) bool {
	if c.maxFrameBytes <= 0 {
		return false
	}
	payloadLen := len(e.Payload)
	evtWire := payloadLen + 3 // tag(1) + varint(1) + type(1)
	if payloadLen+1 >= 128 {  // body_len ≥ 128 → 2-byte varint
		evtWire++
	}
	// Matches addItem's flush condition: pendingBytes[chId]+evtWire+frameHeaderBudget >= maxFrameBytes
	// with pendingBytes[chId] == 0 (no previous events in this frame).
	return evtWire+frameHeaderBudget >= c.maxFrameBytes
}

// pipelineIdle reports whether all channels with pending events have empty
// reliable send pipelines (i.e. no frames are currently in-flight waiting for
// ACK).  For unreliable channels (rs == nil) the pipeline is always idle.
// Called lock-free from the coalescer goroutine; reads numPendingFast atomically.
func (c *coalescer) pipelineIdle(pending map[uint16][]*Event) bool {
	for chId := range pending {
		if v, ok := c.conn.channelMap.Load(chId); ok {
			if rs := v.(*Channel).reliable.Load(); rs != nil {
				if rs.numPendingFast.Load() > 0 {
					return false
				}
			}
		}
	}
	return true
}

// push enqueues an event for coalesced delivery.  It blocks only when the
// input buffer is full (natural back-pressure).
func (c *coalescer) push(ctx context.Context, channelId uint16, e *Event) error {
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
	pending := make(map[uint16][]*Event)
	pendingBytes := make(map[uint16]int)
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
	// For unreliable channels, the Frame struct is borrowed from ackFramePool and
	// returned immediately after sess.send() — saving one allocation per flush.
	// For reliable channels, the Frame is heap-allocated because it must remain
	// alive in the pending ring until the ACK arrives.
	sendFrame := func(sess *session, chId uint16, events []*Event) {
		var rs *reliableState
		if v, ok := c.conn.channelMap.Load(chId); ok {
			rs = v.(*Channel).reliable.Load()
		}

		var frame *Frame
		if rs != nil {
			frame = &Frame{ChannelId: chId, Events: events}
			if err := rs.preSend(frame, nil); err != nil {
				dbg("coalescer: reliable preSend failed, dropping events",
					"channel_id", chId, "count", len(events), "err", err)
				DebugCoalescerPreSendFailed.Add(int64(len(events)))
				return
			}
		} else {
			frame = ackFramePool.Get().(*Frame)
			frame.ChannelId = chId
			frame.Events = events
		}

		if err := sess.send(frame); err != nil {
			dbg("coalescer: send failed, dropping events",
				"channel_id", chId, "count", len(events), "err", err)
			DebugCoalescerSendFailed.Add(int64(len(events)))
		}

		if rs == nil {
			// Unreliable: return the Frame struct to the pool now that sending
			// is complete.  Clear Events so the event pointers are not pinned.
			frame.Events = nil
			frame.ChannelId = 0
			ackFramePool.Put(frame)
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
	flushOne := func(sess *session, chId uint16) {
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

	addItem := func(item coalesceItem) (fullChannelId uint16, full bool) {
		chId := item.channelId
		pending[chId] = append(pending[chId], item.event)
		// Limit events per frame to the channel's reliable window size.
		// Without this, the coalescer may batch hundreds of events into a
		// single frame (for large MTUs with small payloads), producing a
		// frame whose evtCount permanently exceeds the peer's peerWindow
		// (which is bounded by cap(ch.events) = EventBufSize).  preSend
		// would then block forever.
		if v, ok := c.conn.channelMap.Load(chId); ok {
			if rs := v.(*Channel).reliable.Load(); rs != nil {
				if len(pending[chId]) >= rs.cfg.WindowSize {
					return chId, true
				}
			}
		}
		if c.maxFrameBytes > 0 {
			// Track estimated wire bytes for this event to match the actual frame
			// encoding from Frame.AppendMarshal.  Each event encodes as:
			//   field tag 0x0A (1 byte) + varint(body_len) + type(1) + payload
			// where body_len = 1 + len(payload).
			//   body_len ≤ 127  → varint = 1 byte → overhead = 3
			//   body_len ≥ 128  → varint = 2 bytes → overhead = 4
			// Using raw payload bytes alone understates the frame size, causing
			// coalesced frames to exceed maxFragPayload and be split into 2 UDP
			// fragments instead of 1, doubling the in-flight packet count.
			payloadLen := len(item.event.Payload)
			evtWire := payloadLen + 3 // tag(1) + varint(1) + type(1)
			if payloadLen+1 >= 128 {  // body_len ≥ 128 → 2-byte varint
				evtWire++
			}
			pendingBytes[chId] += evtWire
			// Flush when the current frame is large enough that adding one more
			// event of the same size (plus frame-level header fields) would
			// exceed maxFrameBytes.
			if pendingBytes[chId]+evtWire+frameHeaderBudget >= c.maxFrameBytes {
				return chId, true
			}
		}
		return 0, false
	}

	for {
		select {
		case resp := <-c.flushC:
			// Non-destructive flush from Conn.Flush(): send all pending events
			// and signal completion, then continue running so further sends work.
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
			close(resp)
			// timerC is now nil; it will be re-armed on the next item.

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
				// Nagle-equivalent: if all pending channels' send pipelines are
				// idle (no unACKed frames in-flight), flush immediately to
				// minimise latency.  When in-flight frames exist, arm the timer
				// to coalesce more events into the same batch before flushing.
				if c.pipelineIdle(pending) {
					if sess := getSession(); sess != nil {
						flushAll(sess)
					}
				} else {
					// Arm the one-shot flush timer on the first item of a new batch.
					if timer == nil {
						timer = time.NewTimer(c.interval)
					} else {
						timer.Reset(c.interval)
					}
					timerC = timer.C
				}
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
