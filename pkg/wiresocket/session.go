package wiresocket

import (
	"encoding/binary"
	"net"
	"sync/atomic"
	"time"

	"example.com/pulse/pulse/pkg/wiresocket/proto"
)

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
	// Transport keys.
	sendKey [32]byte
	recvKey [32]byte

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

	// Buffered channel delivering decrypted events to the application.
	events chan *proto.Event

	// Closed to signal teardown.
	done chan struct{}

	// Activity tracking.
	lastRecv     atomic.Value // stores time.Time — updated on every received packet (any type)
	lastDataRecv atomic.Value // stores time.Time — updated only on received data packets
	lastSend     atomic.Value // stores time.Time — updated on every sent packet
	created      time.Time
}

func newSession(
	localIndex, remoteIndex uint32,
	sendKey, recvKey [32]byte,
	addr *net.UDPAddr,
	conn *net.UDPConn,
	eventBuf int,
) *session {
	s := &session{
		sendKey:     sendKey,
		recvKey:     recvKey,
		remoteIndex: remoteIndex,
		localIndex:  localIndex,
		remoteAddr:  addr,
		udpConn:     conn,
		events:      make(chan *proto.Event, eventBuf),
		done:        make(chan struct{}),
		created:     time.Now(),
	}
	now := time.Now()
	s.lastRecv.Store(now)
	s.lastDataRecv.Store(now)
	s.lastSend.Store(now)
	dbg("session created",
		"local_index", localIndex,
		"remote_index", remoteIndex,
		"remote_addr", addr.String(),
	)
	return s
}

// close signals teardown and drains the event channel.
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

// send encrypts frame and writes it to the remote peer over the shared
// UDPConn.  It is safe to call from multiple goroutines simultaneously.
func (s *session) send(frame *proto.Frame) error {
	counter, ok := s.nextCounter()
	if !ok {
		return ErrConnClosed
	}

	plain := frame.Marshal()
	hdr := marshalDataHeader(s.remoteIndex, counter)
	ciphertext := encryptAEAD(hdr, s.sendKey, counter, nil, plain)

	dbg("send packet",
		"local_index", s.localIndex,
		"remote_index", s.remoteIndex,
		"counter", counter,
		"plain_bytes", len(plain),
		"packet_bytes", len(ciphertext),
	)
	_, err := s.udpConn.WriteToUDP(ciphertext, s.remoteAddr)
	if err == nil {
		s.lastSend.Store(time.Now())
	}
	return err
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

	ciphertext := encryptAEAD(hdr, s.sendKey, counter, nil, nil)
	dbg("send keepalive",
		"local_index", s.localIndex,
		"remote_addr", s.remoteAddr.String(),
	)
	_, err := s.udpConn.WriteToUDP(ciphertext, s.remoteAddr)
	if err == nil {
		s.lastSend.Store(time.Now())
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
	if _, err := decryptAEAD(s.recvKey, counter, nil, b[sizeDataHeader:]); err != nil {
		dbg("recv: keepalive decrypt failed", "local_index", s.localIndex, "counter", counter, "err", err)
		return false
	}
	s.replay.update(counter)
	s.lastRecv.Store(time.Now())
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

	ciphertext := encryptAEAD(hdr, s.sendKey, counter, nil, nil)
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

	// Header is used as AAD-free AEAD (we authenticate only the payload);
	// the counter itself is part of the nonce so no AAD is needed.
	plain, err := decryptAEAD(s.recvKey, hdr.Counter, nil, b[sizeDataHeader:])
	if err != nil {
		dbg("recv: decrypt failed", "local_index", s.localIndex, "counter", hdr.Counter, "err", err)
		return false
	}
	s.replay.update(hdr.Counter)
	now := time.Now()
	s.lastRecv.Store(now)
	s.lastDataRecv.Store(now)

	if len(plain) == 0 {
		return true // empty data frame — nothing to deliver
	}

	frame, err := proto.UnmarshalFrame(plain)
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
	for _, e := range frame.Events {
		select {
		case s.events <- e:
		case <-s.done:
			return false
		default:
			// Drop oldest if buffer is full rather than blocking.
			dbg("recv: event buffer full, dropping oldest", "local_index", s.localIndex)
			select {
			case <-s.events:
			default:
			}
			select {
			case s.events <- e:
			default:
			}
		}
	}
	return true
}

// dataActivity returns the most recent time the session sent or received a
// data packet.  Keepalive receipt is intentionally excluded so that receiving
// a keepalive does not suppress sending one in response.
func (s *session) dataActivity() time.Time {
	lastSend := s.lastSend.Load().(time.Time)
	lastDataRecv := s.lastDataRecv.Load().(time.Time)
	if lastDataRecv.After(lastSend) {
		return lastDataRecv
	}
	return lastSend
}

// isExpired reports whether the session has been idle long enough to be torn
// down.  Any received packet (including keepalives) counts as activity so that
// a peer sending keepalives is not incorrectly declared dead.
func (s *session) isExpired() bool {
	lastRecv := s.lastRecv.Load().(time.Time)
	return time.Since(lastRecv) > sessionTimeout
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
	return time.Since(s.dataActivity()) > keepaliveInterval
}
