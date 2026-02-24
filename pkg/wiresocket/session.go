package wiresocket

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"sync/atomic"
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

	// router is called directly from the receive hot-path to deliver decoded
	// events to their destination channel.  Set once by Conn.wireSession
	// before the read-loop goroutine starts; never modified after that, so no
	// synchronisation is needed beyond the goroutine-start happens-before.
	router func(channelId uint8, e *Event)

	// onClose, if non-nil, is called once by close() to propagate teardown.
	// Used by non-persistent Conns to close all channels when the session ends.
	onClose func()

	// eventBuf is the per-channel event buffer depth; stored here so newConn
	// can read it without needing a separate parameter.
	eventBuf int

	// Closed to signal teardown.
	done chan struct{}

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
	return s
}

// close signals teardown.
func (s *session) close() {
	select {
	case <-s.done:
	default:
		dbg("session closed",
			"local_index", s.localIndex,
			"remote_index", s.remoteIndex,
			"remote_addr", s.remoteAddr.String(),
		)
		close(s.done)
		if s.onClose != nil {
			s.onClose()
		}
	}
}

// nextCounter atomically allocates the next send counter value.
// If the counter wraps around at 2^64 (all nonce values exhausted), the
// session is closed and (0, false) is returned — the caller must not send.
// Closing the session forces the application to re-dial, which performs a
// fresh Noise IK handshake and establishes new transport keys.
func (s *session) nextCounter() (uint64, bool) {
	next := atomic.AddUint64(&s.sendCounter, 1)
	if next == 0 {
		dbg("send counter wrapped at 2^64, closing session to force re-handshake",
			"local_index", s.localIndex,
		)
		s.close()
		return 0, false
	}
	return next - 1, true
}

// isDone reports whether the session has been closed.
func (s *session) isDone() bool {
	select {
	case <-s.done:
		return true
	default:
		return false
	}
}

// send encrypts frame and writes it to the remote peer.  Frames larger than
// maxFragPayload are automatically split across multiple typeDataFragment
// packets.  It is safe to call from multiple goroutines simultaneously.
func (s *session) send(frame *Frame) error {
	bp := sendBufPool.Get().(*[]byte)

	// Marshal the frame after a sizeDataHeader-byte placeholder for the header.
	// Using a three-index slice lets us start from len=0 while still giving
	// AppendMarshal the correct starting length.
	buf := frame.AppendMarshal((*bp)[0:sizeDataHeader:cap(*bp)])
	*bp = buf
	plain := buf[sizeDataHeader:]

	if len(plain) > s.maxFragPayload {
		err := s.sendFragments(plain) // plain is valid; bp held for the duration
		sendBufPool.Put(bp)
		return err
	}

	counter, ok := s.nextCounter()
	if !ok {
		sendBufPool.Put(bp)
		return ErrConnClosed
	}

	// Write the data header in-place into the placeholder region.
	buf[0] = typeData
	buf[1], buf[2], buf[3] = 0, 0, 0
	binary.LittleEndian.PutUint32(buf[4:], s.remoteIndex)
	binary.LittleEndian.PutUint64(buf[8:], counter)

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
	_, err := s.udpConn.WriteToUDP(packet, s.remoteAddr)
	if err == nil {
		s.lastSend.Store(time.Now().UnixNano())
	}
	sendBufPool.Put(bp)
	return err
}

// sendFragments splits plain into s.maxFragPayload-sized chunks, encrypts each
// into its own pool buffer, and sends all fragments in one WriteBatch syscall
// (sendmmsg on Linux; a sendmsg loop on other platforms).
func (s *session) sendFragments(plain []byte) error {
	fragCount := (len(plain) + s.maxFragPayload - 1) / s.maxFragPayload
	if fragCount > 65535 {
		return errors.New("wiresocket: frame too large to fragment (exceeds 65535 fragments)")
	}

	frameID := s.fragCounter.Add(1)
	dbg("send fragments",
		"local_index", s.localIndex,
		"remote_index", s.remoteIndex,
		"frame_id", frameID,
		"frag_count", fragCount,
		"total_bytes", len(plain),
	)

	// Encrypt all fragments into separate pool buffers and build the batch.
	msgs := make([]ipv4.Message, fragCount)
	bps := make([]*[]byte, fragCount)

	for i := 0; i < fragCount; i++ {
		start := i * s.maxFragPayload
		end := start + s.maxFragPayload
		if end > len(plain) {
			end = len(plain)
		}
		fragData := plain[start:end]

		totalSz := sizeDataHeader + sizeFragmentHeader + len(fragData)

		bp := sendBufPool.Get().(*[]byte)
		if cap(*bp) < totalSz+sizeAEADTag {
			*bp = make([]byte, 0, totalSz+sizeAEADTag)
		}
		buf := (*bp)[0:totalSz:cap(*bp)]

		counter, ok := s.nextCounter()
		if !ok {
			// Return all buffers allocated so far, then the current one.
			for j := 0; j < i; j++ {
				sendBufPool.Put(bps[j])
			}
			sendBufPool.Put(bp)
			return ErrConnClosed
		}

		// Data header.
		buf[0] = typeDataFragment
		buf[1], buf[2], buf[3] = 0, 0, 0
		binary.LittleEndian.PutUint32(buf[4:], s.remoteIndex)
		binary.LittleEndian.PutUint64(buf[8:], counter)

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
		bps[i] = bp

		msgs[i] = ipv4.Message{
			Buffers: [][]byte{packet},
			Addr:    s.remoteAddr,
		}
	}

	// Send all fragments — one syscall for the entire frame on Linux
	// (sendmmsg via PacketConn.WriteBatch), or a plain WriteToUDP loop elsewhere.
	// ipv4.Message and ipv6.Message are both aliases for socket.Message, so the
	// same msgs slice is accepted by both WriteBatch overloads without conversion.
	var sendErr error
	switch {
	case s.pc != nil:
		sent := 0
		for sent < fragCount {
			n, err := s.pc.WriteBatch(msgs[sent:], 0)
			sent += n
			if err != nil {
				sendErr = err
				break
			}
		}
	case s.pc6 != nil:
		sent := 0
		for sent < fragCount {
			n, err := s.pc6.WriteBatch(msgs[sent:], 0)
			sent += n
			if err != nil {
				sendErr = err
				break
			}
		}
	default:
		for _, msg := range msgs {
			if _, err := s.udpConn.WriteToUDP(msg.Buffers[0], s.remoteAddr); err != nil {
				sendErr = err
				break
			}
		}
	}

	for _, bp := range bps {
		sendBufPool.Put(bp)
	}
	if sendErr != nil {
		return sendErr
	}
	s.lastSend.Store(time.Now().UnixNano())
	return nil
}

// sendKeepalive sends a typeKeepalive packet (AEAD over empty payload).
func (s *session) sendKeepalive() error {
	counter, ok := s.nextCounter()
	if !ok {
		return ErrConnClosed
	}

	hdr := make([]byte, sizeDataHeader)
	hdr[0] = typeKeepalive
	hdr[4] = byte(s.remoteIndex)
	hdr[5] = byte(s.remoteIndex >> 8)
	hdr[6] = byte(s.remoteIndex >> 16)
	hdr[7] = byte(s.remoteIndex >> 24)
	binary.LittleEndian.PutUint64(hdr[8:], counter)

	ciphertext := s.sendAEAD.Seal(hdr, makeNonce(counter), nil, nil)
	dbg("send keepalive",
		"local_index", s.localIndex,
		"remote_addr", s.remoteAddr.String(),
	)
	_, err := s.udpConn.WriteToUDP(ciphertext, s.remoteAddr)
	if err == nil {
		s.lastSend.Store(time.Now().UnixNano())
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
	counter := binary.LittleEndian.Uint64(b[8:])
	if !s.replay.check(counter) {
		dbg("recv: keepalive replay rejected", "local_index", s.localIndex, "counter", counter)
		return false
	}
	if _, err := s.recvAEAD.Open(nil, makeNonce(counter), b[sizeDataHeader:], nil); err != nil {
		dbg("recv: keepalive decrypt failed", "local_index", s.localIndex, "counter", counter, "err", err)
		return false
	}
	s.replay.update(counter)
	s.lastRecv.Store(time.Now().UnixNano())
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
	hdr := make([]byte, sizeDataHeader)
	hdr[0] = typeDisconnect
	hdr[4] = byte(s.remoteIndex)
	hdr[5] = byte(s.remoteIndex >> 8)
	hdr[6] = byte(s.remoteIndex >> 16)
	hdr[7] = byte(s.remoteIndex >> 24)
	hdr[8] = byte(counter)
	hdr[9] = byte(counter >> 8)
	hdr[10] = byte(counter >> 16)
	hdr[11] = byte(counter >> 24)
	hdr[12] = byte(counter >> 32)
	hdr[13] = byte(counter >> 40)
	hdr[14] = byte(counter >> 48)
	hdr[15] = byte(counter >> 56)

	ciphertext := s.sendAEAD.Seal(hdr, makeNonce(counter), nil, nil)
	dbg("send disconnect",
		"local_index", s.localIndex,
		"remote_addr", s.remoteAddr.String(),
	)
	_, err := s.udpConn.WriteToUDP(ciphertext, s.remoteAddr)
	return err
}

// receive decrypts an incoming data packet and delivers its events.
// b is the full UDP payload including the 16-byte DataHeader.
// Returns false if the packet should be silently dropped (replay, bad tag, etc.).
func (s *session) receive(b []byte) bool {
	hdr, err := parseDataHeader(b)
	if err != nil {
		dbg("recv: bad data header", "local_index", s.localIndex, "err", err)
		return false
	}
	if !s.replay.check(hdr.Counter) {
		dbg("recv: replay rejected", "local_index", s.localIndex, "counter", hdr.Counter)
		return false // replay or too old
	}

	// Decrypt into a pool buffer to avoid per-packet heap allocation.
	bp := recvBufPool.Get().(*[]byte)
	var nonce [12]byte
	binary.LittleEndian.PutUint64(nonce[4:], hdr.Counter)
	plain, err := s.recvAEAD.Open((*bp)[:0], nonce[:], b[sizeDataHeader:], nil)
	if err != nil {
		recvBufPool.Put(bp)
		dbg("recv: decrypt failed", "local_index", s.localIndex, "counter", hdr.Counter, "err", err)
		return false
	}
	// Track the slice in case Open reallocated (pool buffer was too small).
	*bp = plain[:cap(plain)]

	s.replay.update(hdr.Counter)
	now := time.Now().UnixNano()
	s.lastRecv.Store(now)
	s.lastDataRecv.Store(now)

	if len(plain) == 0 {
		recvBufPool.Put(bp)
		return true // empty data frame — nothing to deliver
	}

	frame, err := UnmarshalFrame(plain)
	// Return the pool buffer now: UnmarshalFrame copies Event.Payload (frame.go),
	// so the pool memory is no longer referenced after this point.
	recvBufPool.Put(bp)
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
		for _, e := range frame.Events {
			r(frame.ChannelId, e)
		}
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

	counter := binary.LittleEndian.Uint64(b[8:])
	if !s.replay.check(counter) {
		dbg("recv: fragment replay rejected", "local_index", s.localIndex, "counter", counter)
		return false
	}

	// Decrypt into a pool buffer.
	bp := recvBufPool.Get().(*[]byte)
	var nonce [12]byte
	binary.LittleEndian.PutUint64(nonce[4:], counter)
	plain, err := s.recvAEAD.Open((*bp)[:0], nonce[:], b[sizeDataHeader:], nil)
	if err != nil {
		recvBufPool.Put(bp)
		dbg("recv: fragment decrypt failed", "local_index", s.localIndex, "counter", counter, "err", err)
		return false
	}
	*bp = plain[:cap(plain)] // track any realloc by Open
	s.replay.update(counter)

	if len(plain) < sizeFragmentHeader {
		recvBufPool.Put(bp)
		dbg("recv: fragment payload too short", "local_index", s.localIndex)
		return false
	}

	frameID := binary.LittleEndian.Uint32(plain[0:])
	fragIndex := binary.LittleEndian.Uint16(plain[4:])
	fragCount := binary.LittleEndian.Uint16(plain[6:])
	data := plain[sizeFragmentHeader:] // zero-copy view into pool buffer

	if fragCount == 0 || int(fragIndex) >= int(fragCount) {
		recvBufPool.Put(bp)
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
			recvBufPool.Put(bp)
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
	} else if rbuf.total != fragCount {
		s.fragMu.Unlock()
		recvBufPool.Put(bp)
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
		recvBufPool.Put(bp)
		dbg("recv: duplicate fragment ignored",
			"local_index", s.localIndex,
			"frame_id", frameID,
			"frag_index", fragIndex,
		)
	}

	complete := rbuf.received == rbuf.total
	var assembled []byte
	if complete {
		total := 0
		for _, f := range rbuf.frags {
			total += len(f)
		}
		assembled = make([]byte, 0, total)
		for _, f := range rbuf.frags {
			assembled = append(assembled, f...)
		}
		// Return all pool buffers now that the data has been copied.
		for _, fragBp := range rbuf.bufs {
			if fragBp != nil {
				recvBufPool.Put(fragBp)
			}
		}
		delete(s.fragBufs, frameID)
	}
	s.fragMu.Unlock()

	if !complete {
		return true
	}

	now := time.Now().UnixNano()
	s.lastRecv.Store(now)
	s.lastDataRecv.Store(now)

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
		for _, e := range frame.Events {
			r(frame.ChannelId, e)
		}
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
					recvBufPool.Put(bp)
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
