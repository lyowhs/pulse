package wiresocket

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// maxReassemblyBufs is the maximum number of incomplete fragmented frames
// buffered per session at one time.
const maxReassemblyBufs = 64

// reassemblyBuf accumulates fragments for a single fragmented frame.
type reassemblyBuf struct {
	frags    [][]byte  // indexed by frag_index; nil slot = not yet received; slice views into pool bufs
	bufs     []*[]byte // pool buffer pointer per fragment; kept alive until reassembly or GC
	received uint16    // number of fragments received so far
	total    uint16    // total expected (from frag_count)
	lastSeen time.Time // updated on each received fragment; used for GC
}

// Session timing constants (WireGuard-inspired).
const (
	keepaliveInterval = 10 * time.Second
	sessionTimeout    = 180 * time.Second
	rekeyAfterTime    = 180 * time.Second
	// rekeyAfterMessages: after 2^60 packets, re-key (effectively infinite
	// for most workloads; included for completeness).
	rekeyAfterMessages = uint64(1) << 60
)

// sendLimiter is implemented by tokenBucket (static rate) and aimdController
// (dynamic AIMD rate).  nil means unlimited — callers guard with != nil.
type sendLimiter interface {
	wait(done <-chan struct{}, n int) error
}

// session holds all state for one established peer connection.
type session struct {
	// Transport keys (kept for reference; AEADs are derived from them).
	sendKey [32]byte
	recvKey [32]byte

	// Cached AEAD instances derived from transport keys — created once in
	// newSession and reused for every encrypt/decrypt to avoid per-packet
	// cipher setup overhead.
	sendAEAD cipher.AEAD
	recvAEAD cipher.AEAD

	// Maximum plaintext bytes per outgoing fragment (derived from MaxPacketSize).
	maxFragPayload int

	// Monotonic send counter — atomically incremented.
	sendCounter uint64

	// Replay-protection window for received packets.
	replay replayWindow

	// Remote peer's session index — used as ReceiverIndex in outgoing data
	// packets so the peer can route them back to this session.
	remoteIndex uint32

	// Our local session index — used by the remote as ReceiverIndex in their
	// outgoing data packets.
	localIndex uint32

	// UDP address of the remote peer.
	remoteAddr *net.UDPAddr

	// Shared UDP connection used to write outgoing packets.
	udpConn *net.UDPConn

	// pc / pc6 wrap udpConn for WriteBatch (sendmmsg on Linux).
	// Exactly one is set depending on the socket's address family; the other
	// is nil.  sendFragments dispatches to whichever is non-nil.
	pc  *ipv4.PacketConn
	pc6 *ipv6.PacketConn

	// router is called directly from the receive hot-path to deliver a decoded
	// Frame (with all reliability fields intact) to the Conn-level dispatcher.
	// Set once by Conn.wireSession before the read-loop goroutine starts;
	// never modified after that, so no synchronisation is needed beyond the
	// goroutine-start happens-before.
	router func(frame *Frame)

	// rateLimiter, when non-nil, throttles outgoing bytes to a configured
	// rate.  nil means unlimited (zero overhead on the send hot-path).
	// Implements either a static tokenBucket or an aimdController.
	rateLimiter sendLimiter

	// onClose, if non-nil, is called once by close() to propagate teardown.
	// Used by non-persistent Conns to close all channels when the session ends.
	onClose func()

	// eventBuf is the per-channel event buffer depth; stored here so newConn
	// can read it without needing a separate parameter.
	eventBuf int

	// Closed to signal teardown.
	done      chan struct{}
	closed    atomic.Bool // set to true before done is closed; enables a lock-free isDone fast-path
	closeOnce sync.Once   // ensures close() is idempotent without a TOCTOU race

	// removed is set to true by the first server code path (handleDisconnect,
	// gc, or the OnConnect goroutine defer) that removes this session from the
	// server's routing table and decrements totalSessions.  The remaining paths
	// find it already set and skip the decrement, preventing double-counting.
	removed atomic.Bool

	// How long without any received packet before declaring the peer dead.
	timeout time.Duration

	// How often to send keepalive probes when data is idle.
	keepalive time.Duration

	// Maximum number of partially-reassembled fragmented frames buffered.
	maxFragBufs int

	// Activity tracking (unix nanoseconds; cheaper than atomic.Value+time.Time).
	lastRecv     atomic.Int64 // updated on every received packet (any type)
	lastDataRecv atomic.Int64 // updated only on received data packets
	lastSend     atomic.Int64 // updated on every sent packet
	created      time.Time

	// Fragment reassembly (receive side) and outgoing frame ID counter (send side).
	fragCounter atomic.Uint32
	fragMu      sync.Mutex
	fragBufs    map[uint32]*reassemblyBuf

	// sendQ is the async send queue for encrypted single-packet frames.
	// Populated by send(); drained by the flushLoop goroutine, which calls
	// WriteBatch (sendmmsg on Linux) to amortise per-syscall overhead.
	// sendFragments bypasses the queue (it already builds its own batch).
	sendQ chan sendQueueItem

	// flushDone is closed by flushLoop when it exits.  clientReadLoop waits
	// on this before closing the UDP socket so that any packets already queued
	// in sendQ are transmitted before the socket becomes invalid.
	flushDone chan struct{}
}

func newSession(
	localIndex, remoteIndex uint32,
	sendKey, recvKey [32]byte,
	addr *net.UDPAddr,
	conn *net.UDPConn,
	eventBuf int,
	timeout time.Duration,
	keepalive time.Duration,
	maxFragBufs int,
	maxFragPayload int,
	sendRateLimitBPS int64,
) *session {
	sendAEAD, err := chacha20poly1305.New(sendKey[:])
	if err != nil {
		panic("wiresocket: newSession sendAEAD: " + err.Error())
	}
	recvAEAD, err := chacha20poly1305.New(recvKey[:])
	if err != nil {
		panic("wiresocket: newSession recvAEAD: " + err.Error())
	}
	// Wrap udpConn with the address-family-appropriate PacketConn so that
	// sendFragments can use WriteBatch (sendmmsg on Linux).
	// ipv4.PacketConn requires an IPv4 socket; ipv6.PacketConn requires IPv6.
	// Mixing them causes EINVAL on macOS (sendmsg with mismatched control msgs).
	var pc *ipv4.PacketConn
	var pc6 *ipv6.PacketConn
	if laddr, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		if laddr.IP.To4() != nil {
			pc = ipv4.NewPacketConn(conn)
		} else if laddr.IP != nil {
			// newIPv6PacketConn is build-tagged: returns a real *ipv6.PacketConn
			// on Linux (where sendmmsg exists) and nil elsewhere (macOS/Windows
			// where ipv6 sendmsg control messages fail on dual-stack sockets).
			pc6 = newIPv6PacketConn(conn)
		}
	}

	var rl sendLimiter
	if sendRateLimitBPS > 0 {
		rl = newTokenBucket(sendRateLimitBPS)
	}

	s := &session{
		sendKey:        sendKey,
		recvKey:        recvKey,
		sendAEAD:       sendAEAD,
		recvAEAD:       recvAEAD,
		maxFragPayload: maxFragPayload,
		remoteIndex:    remoteIndex,
		localIndex:     localIndex,
		remoteAddr:     addr,
		udpConn:        conn,
		pc:             pc,
		pc6:            pc6,
		eventBuf:       eventBuf,
		done:           make(chan struct{}),
		created:        time.Now(),
		timeout:        timeout,
		keepalive:      keepalive,
		maxFragBufs:    maxFragBufs,
		rateLimiter:    rl,
		sendQ:          make(chan sendQueueItem, sendQueueCapFor(eventBuf)),
		flushDone:      make(chan struct{}),
	}
	now := time.Now().UnixNano()
	s.lastRecv.Store(now)
	s.lastDataRecv.Store(now)
	s.lastSend.Store(now)
	dbg("session created",
		"local_index", localIndex,
		"remote_index", remoteIndex,
		"remote_addr", addr.String(),
		"timeout", timeout,
		"keepalive", keepalive,
	)
	// Start the async send-queue flush goroutine (Item 1 optimisation).
	go func() {
		s.flushLoop()
		close(s.flushDone)
	}()
	return s
}

// close signals teardown.  It is safe to call from multiple goroutines
// simultaneously; only the first call takes effect (sync.Once guarantees
// that the channel is never closed twice, eliminating the channel-select
// TOCTOU race that was present in the previous select-based implementation).
func (s *session) close() {
	s.closeOnce.Do(func() {
		dbg("session closed",
			"local_index", s.localIndex,
			"remote_index", s.remoteIndex,
			"remote_addr", s.remoteAddr.String(),
		)
		s.closed.Store(true)
		close(s.done)
		if s.onClose != nil {
			s.onClose()
		}
	})
}

// maxOnWireCounter is the exclusive upper bound on the 48-bit on-wire counter.
// Counters 0..maxOnWireCounter-1 fit in the 6-byte data header field.
const maxOnWireCounter = uint64(1) << 48

// nextCounter atomically allocates the next send counter value.
// If all 48-bit counter values are exhausted (2^48 packets sent), the session
// is closed and (0, false) is returned — the caller must not send.
// Closing the session forces the application to re-dial, which performs a
// fresh Noise IK handshake and establishes new transport keys.
func (s *session) nextCounter() (uint64, bool) {
	next := atomic.AddUint64(&s.sendCounter, 1)
	if next == 0 || next > maxOnWireCounter {
		dbg("send counter exhausted, closing session to force re-handshake",
			"local_index", s.localIndex,
			"counter", next,
		)
		s.close()
		return 0, false
	}
	return next - 1, true
}

// isDone reports whether the session has been closed.
// Uses an atomic flag rather than a channel-select for a cheaper hot-path read.
func (s *session) isDone() bool { return s.closed.Load() }

// lazyTimeThreshold is the minimum elapsed time before we update the
// lastSend/lastRecv atomic timestamps.  At packet rates above ~1000/s,
// avoiding the atomic store on every packet reduces cross-core cache
// coherency traffic on the lastSend/lastRecv cache lines (item 9 optimization).
// The threshold is well below all timeout and keepalive intervals (seconds).
const lazyTimeThreshold = int64(time.Millisecond)

// touchLastSend updates s.lastSend to now if more than lazyTimeThreshold has
// elapsed since the last update.  Saves redundant atomic stores at high packet
// rates while keeping the timestamp accurate to within 1 ms.
func (s *session) touchLastSend() {
	now := time.Now().UnixNano()
	if now-s.lastSend.Load() > lazyTimeThreshold {
		s.lastSend.Store(now)
	}
}

// touchLastRecv updates s.lastRecv (and optionally s.lastDataRecv) to now if
// more than lazyTimeThreshold has elapsed since the last update.
func (s *session) touchLastRecv(data bool) {
	now := time.Now().UnixNano()
	if now-s.lastRecv.Load() > lazyTimeThreshold {
		s.lastRecv.Store(now)
	}
	if data && now-s.lastDataRecv.Load() > lazyTimeThreshold {
		s.lastDataRecv.Store(now)
	}
}

// writeRetry calls WriteToUDP and retries on ENOBUFS.
// On macOS the kernel UDP send buffer returns ENOBUFS (errno 55) under load
// rather than blocking.  A brief goroutine yield and retry drains backpressure
// without propagating a spurious error to the caller.
func (s *session) writeRetry(data []byte) error {
	for {
		_, err := s.udpConn.WriteToUDP(data, s.remoteAddr)
		if !errors.Is(err, syscall.ENOBUFS) {
			return err
		}
		runtime.Gosched()
	}
}

// send encrypts frame and writes it to the remote peer.  Frames larger than
// maxFragPayload are automatically split across multiple typeDataFragment
// packets.  It is safe to call from multiple goroutines simultaneously.
func (s *session) send(frame *Frame) error {
	// Right-size the pool buffer: small frames use the 2 KB pool, avoiding
	// the 65 KB buffer that would otherwise pollute L1/L2 cache.
	needed := sizeDataHeader + frame.wireSize() + sizeAEADTag
	bp := getSendBuf(needed)

	// Marshal the frame after a sizeDataHeader-byte placeholder for the header.
	// Using a three-index slice lets us start from len=0 while still giving
	// AppendMarshal the correct starting length.
	buf := frame.AppendMarshal((*bp)[0:sizeDataHeader:cap(*bp)])
	*bp = buf
	plain := buf[sizeDataHeader:]

	if len(plain) > s.maxFragPayload {
		err := s.sendFragments(plain) // plain is valid; bp held for the duration
		putSendBuf(bp)
		return err
	}

	// Rate limit: account for header + ciphertext + AEAD tag.
	if s.rateLimiter != nil {
		n := len(plain) + sizeDataHeader + sizeAEADTag
		if err := s.rateLimiter.wait(s.done, n); err != nil {
			putSendBuf(bp)
			return err
		}
	}

	counter, ok := s.nextCounter()
	if !ok {
		putSendBuf(bp)
		return ErrConnClosed
	}

	// Write the data header in-place into the placeholder region.
	buf[0] = typeData
	buf[1] = 0 // flags
	binary.LittleEndian.PutUint32(buf[2:], s.remoteIndex)
	buf[6] = byte(counter)
	buf[7] = byte(counter >> 8)
	buf[8] = byte(counter >> 16)
	buf[9] = byte(counter >> 24)
	buf[10] = byte(counter >> 32)
	buf[11] = byte(counter >> 40)

	// Seal appends ciphertext to buf[:sizeDataHeader].  Because plain is a
	// sub-slice of the same backing array and ChaCha20 is a stream cipher,
	// XOR-in-place is safe (src and dst have identical pointer+length so
	// chacha20.XORKeyStream treats them as equal, not inexactly overlapping).
	var nonce [12]byte
	binary.LittleEndian.PutUint64(nonce[4:], counter)
	packet := s.sendAEAD.Seal(buf[:sizeDataHeader], nonce[:], plain, nil)

	dbg("send packet",
		"local_index", s.localIndex,
		"remote_index", s.remoteIndex,
		"counter", counter,
		"plain_bytes", len(plain),
		"packet_bytes", len(packet),
	)

	// If the session is already closing, flushLoop may have drained sendQ and
	// exited.  Use synchronous write so late callers (e.g. ackBatcher's final
	// sweep) still deliver their packets.
	if s.closed.Load() {
		err := s.writeRetry(packet)
		putSendBuf(bp)
		if err == nil {
			s.touchLastSend()
		}
		return err
	}

	// Async path: enqueue to flushLoop for batched sendmmsg (Item 1).
	// bp ownership transfers to the queue; flushLoop returns it to the pool.
	//
	// sendQueueCapFor(eventBufSize) sizes the queue to exceed inflightCap so
	// that a full window burst can be enqueued without blocking.  The
	// non-blocking select preserves the parallel pipeline between callers and
	// flushLoop (blocking would serialise them, halving throughput at high
	// frame rates).
	//
	// The synchronous fallback is a true last-resort safety net (OOM, giant
	// buffer, etc.).  Under normal operation the queue never fills because
	// sendQueueCapFor(eventBufSize) > inflightCap, so a sync bypass never
	// reorders frames.
	select {
	case s.sendQ <- sendQueueItem{pkt: packet, bp: bp}:
		s.touchLastSend()
		return nil
	default:
	}
	err := s.writeRetry(packet)
	putSendBuf(bp)
	if err == nil {
		s.touchLastSend()
	}
	return err
}

// fragSendBatch holds the per-call slices used by sendFragments.
// Pooling them eliminates two heap allocations per fragmented-frame send
// (msgs and bps) plus one [][]byte allocation per fragment (Buffers).
type fragSendBatch struct {
	msgs []ipv4.Message // passed directly to WriteBatch
	bps  []*[]byte      // pool-buffer handles; returned to send pool after send
	bufs [][]byte       // backing for msgs[i].Buffers; avoids a [][]byte{} alloc per fragment
}

var fragSendPool = sync.Pool{New: func() any { return &fragSendBatch{} }}

// sendFragments splits plain into s.maxFragPayload-sized chunks, encrypts each
// into its own pool buffer, and sends all fragments in one WriteBatch syscall
// (sendmmsg on Linux; a sendmsg loop on other platforms).
func (s *session) sendFragments(plain []byte) error {
	fragCount := (len(plain) + s.maxFragPayload - 1) / s.maxFragPayload
	if fragCount > 65535 {
		return errors.New("wiresocket: frame too large to fragment (exceeds 65535 fragments)")
	}

	// Rate limit the entire frame up front: total on-wire bytes for all fragments.
	if s.rateLimiter != nil {
		n := len(plain) + fragCount*(sizeDataHeader+sizeFragmentHeader+sizeAEADTag)
		if err := s.rateLimiter.wait(s.done, n); err != nil {
			return err
		}
	}

	frameID := s.fragCounter.Add(1)
	dbg("send fragments",
		"local_index", s.localIndex,
		"remote_index", s.remoteIndex,
		"frame_id", frameID,
		"frag_count", fragCount,
		"total_bytes", len(plain),
	)

	// Borrow a batch struct; grow its slices if the pooled copy is too small.
	fb := fragSendPool.Get().(*fragSendBatch)
	if cap(fb.msgs) < fragCount {
		fb.msgs = make([]ipv4.Message, fragCount)
		fb.bps = make([]*[]byte, fragCount)
		fb.bufs = make([][]byte, fragCount)
	} else {
		fb.msgs = fb.msgs[:fragCount]
		fb.bps = fb.bps[:fragCount]
		fb.bufs = fb.bufs[:fragCount]
	}
	// Clear pointers and return fb to the pool on all exit paths.
	defer func() {
		clear(fb.msgs)
		clear(fb.bps)
		clear(fb.bufs)
		fb.msgs = fb.msgs[:0]
		fb.bps = fb.bps[:0]
		fb.bufs = fb.bufs[:0]
		fragSendPool.Put(fb)
	}()

	// Compute the size class for per-fragment buffers once outside the loop.
	// Each fragment is: sizeDataHeader + sizeFragmentHeader + fragPayload + sizeAEADTag.
	// The largest fragment uses s.maxFragPayload bytes of payload.
	fragBufNeeded := sizeDataHeader + sizeFragmentHeader + s.maxFragPayload + sizeAEADTag

	for i := 0; i < fragCount; i++ {
		start := i * s.maxFragPayload
		end := start + s.maxFragPayload
		if end > len(plain) {
			end = len(plain)
		}
		fragData := plain[start:end]

		totalSz := sizeDataHeader + sizeFragmentHeader + len(fragData)

		bp := getSendBuf(fragBufNeeded)
		if cap(*bp) < totalSz+sizeAEADTag {
			// Undersized buffer (shouldn't happen since getSendBuf allocates
			// at least fragBufNeeded bytes, but guard for safety).
			*bp = make([]byte, 0, fragBufNeeded)
		}
		buf := (*bp)[0:totalSz:cap(*bp)]

		counter, ok := s.nextCounter()
		if !ok {
			// Return buffers for already-built fragments plus the current one.
			for j := 0; j < i; j++ {
				putSendBuf(fb.bps[j])
			}
			putSendBuf(bp)
			return ErrConnClosed // defer cleans up fb
		}

		// Data header.
		buf[0] = typeDataFragment
		buf[1] = 0 // flags
		binary.LittleEndian.PutUint32(buf[2:], s.remoteIndex)
		buf[6] = byte(counter)
		buf[7] = byte(counter >> 8)
		buf[8] = byte(counter >> 16)
		buf[9] = byte(counter >> 24)
		buf[10] = byte(counter >> 32)
		buf[11] = byte(counter >> 40)

		// Fragment header: [frame_id(4)][frag_index(2)][frag_count(2)].
		binary.LittleEndian.PutUint32(buf[sizeDataHeader:], frameID)
		binary.LittleEndian.PutUint16(buf[sizeDataHeader+4:], uint16(i))
		binary.LittleEndian.PutUint16(buf[sizeDataHeader+6:], uint16(fragCount))

		// Copy fragment data (one copy from the caller's plain slice).
		copy(buf[sizeDataHeader+sizeFragmentHeader:], fragData)

		// In-place seal (same backing array; stream cipher XOR is safe).
		fragPlain := buf[sizeDataHeader:totalSz]
		var nonce [12]byte
		binary.LittleEndian.PutUint64(nonce[4:], counter)
		packet := s.sendAEAD.Seal(buf[:sizeDataHeader], nonce[:], fragPlain, nil)

		// Track the (possibly grown) backing array for pool return.
		*bp = packet[:cap(*bp)]
		fb.bps[i] = bp

		// Store the packet ref in fb.bufs so msgs[i].Buffers can be a
		// sub-slice of fb.bufs instead of a freshly-allocated [][]byte{packet}.
		fb.bufs[i] = packet
		fb.msgs[i] = ipv4.Message{
			Buffers: fb.bufs[i : i+1 : i+1],
			Addr:    s.remoteAddr,
		}
	}

	// Send all fragments — one syscall on Linux (sendmmsg via WriteBatch),
	// or a plain loop on other platforms.
	sendErr := s.writeBatchMsgs(fb.msgs)

	for _, bp := range fb.bps {
		putSendBuf(bp)
	}
	if sendErr != nil {
		dbg("send fragments failed",
			"local_index", s.localIndex,
			"remote_index", s.remoteIndex,
			"frame_id", frameID,
			"frag_count", fragCount,
			"err", sendErr,
		)
		return sendErr
	}
	s.touchLastSend()
	return nil
}

// sendKeepalive sends a typeKeepalive packet (AEAD over empty payload).
func (s *session) sendKeepalive() error {
	counter, ok := s.nextCounter()
	if !ok {
		return ErrConnClosed
	}

	// Borrow a pool buffer so the header + AEAD tag don't heap-allocate.
	// sizeKeepalive = sizeDataHeader(16) + sizeAEADTag(16) = 32 bytes → small pool.
	bp := getSendBuf(sizeKeepalive)
	buf := (*bp)[:sizeDataHeader]
	buf[0] = typeKeepalive
	buf[1] = 0 // flags
	binary.LittleEndian.PutUint32(buf[2:], s.remoteIndex)
	buf[6] = byte(counter)
	buf[7] = byte(counter >> 8)
	buf[8] = byte(counter >> 16)
	buf[9] = byte(counter >> 24)
	buf[10] = byte(counter >> 32)
	buf[11] = byte(counter >> 40)

	var nonce [12]byte
	binary.LittleEndian.PutUint64(nonce[4:], counter)
	ciphertext := s.sendAEAD.Seal(buf, nonce[:], nil, nil)

	dbg("send keepalive",
		"local_index", s.localIndex,
		"remote_addr", s.remoteAddr.String(),
	)
	err := s.writeRetry(ciphertext)
	putSendBuf(bp)
	if err != nil {
		dbg("send keepalive failed",
			"local_index", s.localIndex,
			"remote_addr", s.remoteAddr.String(),
			"err", err,
		)
	} else {
		s.touchLastSend()
	}
	return err
}

// receiveKeepalive authenticates an incoming typeKeepalive packet and updates
// lastRecv.  Returns false if the packet is invalid or replayed.
func (s *session) receiveKeepalive(b []byte) bool {
	if len(b) < sizeKeepalive {
		dbg("recv: keepalive packet too short", "local_index", s.localIndex, "len", len(b))
		return false
	}
	counter := uint64(b[6]) | uint64(b[7])<<8 | uint64(b[8])<<16 |
		uint64(b[9])<<24 | uint64(b[10])<<32 | uint64(b[11])<<40
	if !s.replay.check(counter) {
		dbg("recv: keepalive replay rejected", "local_index", s.localIndex, "counter", counter)
		return false
	}
	var nonce [12]byte
	binary.LittleEndian.PutUint64(nonce[4:], counter)
	if _, err := s.recvAEAD.Open(nil, nonce[:], b[sizeDataHeader:], nil); err != nil {
		dbg("recv: keepalive decrypt failed", "local_index", s.localIndex, "counter", counter, "err", err)
		return false
	}
	s.replay.update(counter)
	s.touchLastRecv(false) // keepalive: not a data packet
	dbg("recv keepalive", "local_index", s.localIndex, "remote_addr", s.remoteAddr.String())
	return true
}

// sendDisconnect sends an authenticated disconnect notification to the remote
// peer.  The packet has the same AEAD-over-empty-payload layout as a keepalive
// but uses typeDisconnect (5) so the peer can immediately evict the session.
func (s *session) sendDisconnect() error {
	counter, ok := s.nextCounter()
	if !ok {
		return ErrConnClosed
	}

	// Build a data-style header with typeDisconnect instead of typeData.
	// Borrow a pool buffer so the header + AEAD tag don't heap-allocate.
	bp := getSendBuf(sizeDisconnect)
	buf := (*bp)[:sizeDataHeader]
	buf[0] = typeDisconnect
	buf[1] = 0 // flags
	binary.LittleEndian.PutUint32(buf[2:], s.remoteIndex)
	buf[6] = byte(counter)
	buf[7] = byte(counter >> 8)
	buf[8] = byte(counter >> 16)
	buf[9] = byte(counter >> 24)
	buf[10] = byte(counter >> 32)
	buf[11] = byte(counter >> 40)

	var nonce [12]byte
	binary.LittleEndian.PutUint64(nonce[4:], counter)
	ciphertext := s.sendAEAD.Seal(buf, nonce[:], nil, nil)
	dbg("send disconnect",
		"local_index", s.localIndex,
		"remote_addr", s.remoteAddr.String(),
	)
	// Queue through sendQ so the disconnect is sent AFTER any data frames
	// already in the queue.  This guarantees that the peer receives all data
	// before it tears down the session on the disconnect packet.
	// Fall back to writeRetry if the queue is full.
	select {
	case s.sendQ <- sendQueueItem{pkt: ciphertext, bp: bp}:
		return nil
	default:
	}
	err := s.writeRetry(ciphertext)
	putSendBuf(bp)
	if err != nil {
		dbg("send disconnect failed",
			"local_index", s.localIndex,
			"remote_addr", s.remoteAddr.String(),
			"err", err,
		)
	}
	return err
}

// receive decrypts an incoming data packet and delivers its events.
// b is the full UDP payload including the 16-byte DataHeader.
// Returns false if the packet should be silently dropped (replay, bad tag, etc.).
func (s *session) receive(b []byte) bool {
	DebugSessionReceiveCalls.Add(1)
	hdr, err := parseDataHeader(b)
	if err != nil {
		dbg("recv: bad data header", "local_index", s.localIndex, "err", err)
		return false
	}
	if !s.replay.check(hdr.Counter) {
		DebugReplayRejected.Add(1)
		dbg("recv: replay rejected", "local_index", s.localIndex, "counter", hdr.Counter)
		return false // replay or too old
	}

	// Decrypt into a right-sized pool buffer: routes small frames to the 2 KB
	// pool, keeping the working set in L1/L2 cache.
	cipherLen := len(b) - sizeDataHeader // ciphertext including AEAD tag
	bp := getRecvBuf(cipherLen)
	var nonce [12]byte
	binary.LittleEndian.PutUint64(nonce[4:], hdr.Counter)
	plain, err := s.recvAEAD.Open((*bp)[:0], nonce[:], b[sizeDataHeader:], nil)
	if err != nil {
		putRecvBuf(bp)
		dbg("recv: decrypt failed", "local_index", s.localIndex, "counter", hdr.Counter, "err", err)
		return false
	}
	// Track the slice in case Open reallocated (pool buffer was too small).
	*bp = plain[:cap(plain)]

	s.replay.update(hdr.Counter)
	s.touchLastRecv(true) // data packet

	if len(plain) == 0 {
		dbg("recv: empty data frame", "local_index", s.localIndex, "counter", hdr.Counter)
		putRecvBuf(bp)
		return true // empty data frame — nothing to deliver
	}

	frame, err := UnmarshalFrame(plain)
	// Return the pool buffer now: UnmarshalFrame copies Event.Payload (frame.go),
	// so the pool memory is no longer referenced after this point.
	putRecvBuf(bp)
	if err != nil {
		dbg("recv: frame unmarshal failed", "local_index", s.localIndex, "err", err)
		return false
	}
	dbg("recv packet",
		"local_index", s.localIndex,
		"counter", hdr.Counter,
		"plain_bytes", len(plain),
		"events", len(frame.Events),
	)
	if r := s.router; r != nil {
		r(frame)
	}
	return true
}

// dataActivity returns the most recent time the session sent or received a
// data packet.  Keepalive receipt is intentionally excluded so that receiving
// a keepalive does not suppress sending one in response.
func (s *session) dataActivity() time.Time {
	lastSend := time.Unix(0, s.lastSend.Load())
	lastDataRecv := time.Unix(0, s.lastDataRecv.Load())
	if lastDataRecv.After(lastSend) {
		return lastDataRecv
	}
	return lastSend
}

// receiveFragment decrypts and buffers an incoming typeDataFragment packet.
// When all fragments of a frame have arrived it reassembles and delivers them.
// Returns false if the packet should be silently dropped.
//
// Each decrypted fragment is stored as a zero-copy view into a pool buffer.
// The pool buffer is kept alive inside the reassemblyBuf until the frame is
// complete or the entry is GC'd, at which point all pool buffers are returned.
func (s *session) receiveFragment(b []byte) bool {
	const minLen = sizeDataHeader + sizeFragmentHeader + sizeAEADTag
	if len(b) < minLen {
		dbg("recv: fragment packet too short", "local_index", s.localIndex, "len", len(b))
		return false
	}

	counter := uint64(b[6]) | uint64(b[7])<<8 | uint64(b[8])<<16 |
		uint64(b[9])<<24 | uint64(b[10])<<32 | uint64(b[11])<<40
	if !s.replay.check(counter) {
		dbg("recv: fragment replay rejected", "local_index", s.localIndex, "counter", counter)
		return false
	}

	// Decrypt into a right-sized pool buffer.
	fragCipherLen := len(b) - sizeDataHeader
	bp := getRecvBuf(fragCipherLen)
	var nonce [12]byte
	binary.LittleEndian.PutUint64(nonce[4:], counter)
	plain, err := s.recvAEAD.Open((*bp)[:0], nonce[:], b[sizeDataHeader:], nil)
	if err != nil {
		putRecvBuf(bp)
		dbg("recv: fragment decrypt failed", "local_index", s.localIndex, "counter", counter, "err", err)
		return false
	}
	*bp = plain[:cap(plain)] // track any realloc by Open
	s.replay.update(counter)

	if len(plain) < sizeFragmentHeader {
		putRecvBuf(bp)
		dbg("recv: fragment payload too short", "local_index", s.localIndex)
		return false
	}

	frameID := binary.LittleEndian.Uint32(plain[0:])
	fragIndex := binary.LittleEndian.Uint16(plain[4:])
	fragCount := binary.LittleEndian.Uint16(plain[6:])
	data := plain[sizeFragmentHeader:] // zero-copy view into pool buffer

	if fragCount == 0 || int(fragIndex) >= int(fragCount) {
		putRecvBuf(bp)
		dbg("recv: invalid fragment header",
			"local_index", s.localIndex,
			"frame_id", frameID,
			"frag_index", fragIndex,
			"frag_count", fragCount,
		)
		return false
	}

	s.fragMu.Lock()
	if s.fragBufs == nil {
		s.fragBufs = make(map[uint32]*reassemblyBuf)
	}
	rbuf, ok := s.fragBufs[frameID]
	if !ok {
		if len(s.fragBufs) >= s.maxFragBufs {
			s.fragMu.Unlock()
			putRecvBuf(bp)
			dbg("recv: reassembly buffer full, dropping fragment",
				"local_index", s.localIndex,
				"frame_id", frameID,
			)
			return false
		}
		rbuf = &reassemblyBuf{
			frags:    make([][]byte, fragCount),
			bufs:     make([]*[]byte, fragCount),
			total:    fragCount,
			lastSeen: time.Now(),
		}
		s.fragBufs[frameID] = rbuf
		dbg("recv: new fragment reassembly buffer",
			"local_index", s.localIndex,
			"frame_id",    frameID,
			"frag_count",  fragCount,
		)
	} else if rbuf.total != fragCount {
		s.fragMu.Unlock()
		putRecvBuf(bp)
		dbg("recv: fragment count mismatch",
			"local_index", s.localIndex,
			"frame_id", frameID,
			"got", fragCount,
			"want", rbuf.total,
		)
		return false
	}

	if rbuf.frags[fragIndex] == nil {
		// Store zero-copy view; keep pool buffer alive via bufs.
		rbuf.frags[fragIndex] = data
		rbuf.bufs[fragIndex] = bp // ownership transferred to reassemblyBuf
		rbuf.received++
		rbuf.lastSeen = time.Now()
	} else {
		// Duplicate fragment — discard the pool buffer we just decrypted into.
		putRecvBuf(bp)
		dbg("recv: duplicate fragment ignored",
			"local_index", s.localIndex,
			"frame_id", frameID,
			"frag_index", fragIndex,
		)
	}

	complete := rbuf.received == rbuf.total
	if complete {
		// Remove from the map under the lock so no other worker can reach rbuf.
		// The O(N) copy and pool returns happen outside the lock below.
		delete(s.fragBufs, frameID)
	}
	s.fragMu.Unlock()

	if !complete {
		return true
	}

	// rbuf is exclusively ours: deleted from fragBufs while holding the lock,
	// so no other goroutine can reach it.  Assemble the frame and return pool
	// buffers outside the lock to avoid blocking concurrent fragment workers.
	total := 0
	for _, f := range rbuf.frags {
		total += len(f)
	}
	assembled := make([]byte, 0, total)
	for _, f := range rbuf.frags {
		assembled = append(assembled, f...)
	}
	for _, fragBp := range rbuf.bufs {
		if fragBp != nil {
			putRecvBuf(fragBp)
		}
	}

	s.touchLastRecv(true) // assembled fragment = data packet

	if len(assembled) == 0 {
		return true
	}

	frame, err := UnmarshalFrame(assembled)
	if err != nil {
		dbg("recv: fragment reassembly unmarshal failed",
			"local_index", s.localIndex,
			"frame_id", frameID,
			"err", err,
		)
		return false
	}
	dbg("recv fragment assembled",
		"local_index", s.localIndex,
		"frame_id", frameID,
		"total_bytes", len(assembled),
		"events", len(frame.Events),
	)
	if r := s.router; r != nil {
		r(frame)
	}
	return true
}

// gcFragBufs removes reassembly buffers that have not received a fragment
// within maxAge, preventing unbounded memory growth from incomplete frames.
// Pool buffers held by stale entries are returned before deletion.
func (s *session) gcFragBufs(maxAge time.Duration) {
	deadline := time.Now().Add(-maxAge)
	s.fragMu.Lock()
	for id, buf := range s.fragBufs {
		if buf.lastSeen.Before(deadline) {
			dbg("session: dropping stale fragment buffer",
				"local_index", s.localIndex,
				"frame_id", id,
				"received", buf.received,
				"total", buf.total,
			)
			// Return pool buffers for any fragments already received.
			for _, bp := range buf.bufs {
				if bp != nil {
					putRecvBuf(bp)
				}
			}
			delete(s.fragBufs, id)
		}
	}
	s.fragMu.Unlock()
}

// isExpired reports whether the session has been idle long enough to be torn
// down.  Any received packet (including keepalives) counts as activity so that
// a peer sending keepalives is not incorrectly declared dead.
func (s *session) isExpired() bool {
	lastRecv := time.Unix(0, s.lastRecv.Load())
	return time.Since(lastRecv) > s.timeout
}

// needsRekey reports whether the session has exceeded the recommended key
// lifetime and a new handshake should be initiated.
func (s *session) needsRekey() bool {
	return time.Since(s.created) > rekeyAfterTime ||
		atomic.LoadUint64(&s.sendCounter) >= rekeyAfterMessages
}

// needsKeepalive reports whether data has been idle long enough to warrant a
// keepalive probe.  Keepalive receipt does not reset this timer, so a received
// keepalive will still result in one being sent in response.
func (s *session) needsKeepalive() bool {
	return time.Since(s.dataActivity()) > s.keepalive
}
