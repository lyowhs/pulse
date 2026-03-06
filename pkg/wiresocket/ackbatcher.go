package wiresocket

import "time"

// ackBatcher is a per-Conn goroutine that sends deferred standalone ACKs for
// all reliable channels in one place, replacing per-channel time.AfterFunc
// timers (item 6 optimization).
//
// Previously each channel scheduled its own time.AfterFunc(ACKDelay, sendACK)
// on every received frame.  With N channels at high throughput, this creates
// hundreds of goroutine-per-timer events per second.  The batcher uses a
// single ticker and iterates conn.channelMap once per tick, calling sendACK()
// only on channels where ackDirty is set.
//
// The batcher exits automatically when conn.done closes, so no explicit stop
// is needed for the normal conn lifetime.
type ackBatcher struct {
	conn *Conn
}

// newAckBatcher starts the batcher goroutine for conn and returns the batcher.
// The goroutine exits when conn.done is closed.
func newAckBatcher(conn *Conn) *ackBatcher {
	b := &ackBatcher{conn: conn}
	go b.run()
	return b
}

// run is the batcher goroutine.  It wakes every defaultACKDelay, scans all
// channels, and calls sendACK on any channel that has ackDirty set.
func (b *ackBatcher) run() {
	ticker := time.NewTicker(defaultACKDelay)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			b.sendPendingACKs()
			dbg("ackbatcher: tick", "pending_channels", b.countDirty())
		case <-b.conn.done:
			// Final sweep: deliver any ACKs accumulated since the last tick.
			b.sendPendingACKs()
			dbg("ackbatcher: stopped (conn done)")
			return
		}
	}
}

// sendPendingACKs iterates all channels and sends a standalone ACK for each
// channel that has ackDirty set.  sendACK() itself acquires recvMu and
// double-checks the flag, so concurrent piggybacks are race-free.
func (b *ackBatcher) sendPendingACKs() {
	b.conn.channelMap.Range(func(_, v any) bool {
		ch := v.(*Channel)
		if rs := ch.reliable.Load(); rs != nil {
			// Fast pre-check without the lock (item 7): only call sendACK
			// when there is actually something to send.
			if rs.ackDirty.Load() {
				rs.sendACK()
			}
		}
		return true
	})
}

// countDirty returns the number of channels with ackDirty set.
// Used for debug logging only; not called on the hot path.
func (b *ackBatcher) countDirty() int {
	n := 0
	b.conn.channelMap.Range(func(_, v any) bool {
		ch := v.(*Channel)
		if rs := ch.reliable.Load(); rs != nil && rs.ackDirty.Load() {
			n++
		}
		return true
	})
	return n
}
