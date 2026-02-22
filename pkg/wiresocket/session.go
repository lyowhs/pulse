package wiresocket

import (
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
	lastRecv atomic.Value // stores time.Time
	created  time.Time
}

func newSession(
	localIndex, remoteIndex uint32,
	sendKey, recvKey [32]byte,
	addr *net.UDPAddr,
	conn *net.UDPConn,
	eventBuf int,
) *session {
	s := &session{
		sendKey:    sendKey,
		recvKey:    recvKey,
		remoteIndex: remoteIndex,
		localIndex:  localIndex,
		remoteAddr:  addr,
		udpConn:     conn,
		events:      make(chan *proto.Event, eventBuf),
		done:        make(chan struct{}),
		created:     time.Now(),
	}
	s.lastRecv.Store(time.Now())
	return s
}

// close signals teardown and drains the event channel.
func (s *session) close() {
	select {
	case <-s.done:
	default:
		close(s.done)
	}
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
	counter := atomic.AddUint64(&s.sendCounter, 1) - 1

	plain := frame.Marshal()
	hdr := marshalDataHeader(s.remoteIndex, counter)
	ciphertext := encryptAEAD(hdr, s.sendKey, counter, nil, plain)

	_, err := s.udpConn.WriteToUDP(ciphertext, s.remoteAddr)
	return err
}

// sendKeepalive sends an empty (nil-payload) data packet.
func (s *session) sendKeepalive() error {
	return s.send(&proto.Frame{})
}

// receive decrypts an incoming data packet and delivers its events.
// b is the full UDP payload including the 16-byte DataHeader.
// Returns false if the packet should be silently dropped (replay, bad tag, etc.).
func (s *session) receive(b []byte) bool {
	hdr, err := parseDataHeader(b)
	if err != nil {
		return false
	}
	if !s.replay.check(hdr.Counter) {
		return false // replay or too old
	}

	// Header is used as AAD-free AEAD (we authenticate only the payload);
	// the counter itself is part of the nonce so no AAD is needed.
	plain, err := decryptAEAD(s.recvKey, hdr.Counter, nil, b[sizeDataHeader:])
	if err != nil {
		return false
	}
	s.replay.update(hdr.Counter)
	s.lastRecv.Store(time.Now())

	// Keepalive: empty plaintext.
	if len(plain) == 0 {
		return true
	}

	frame, err := proto.UnmarshalFrame(plain)
	if err != nil {
		return false
	}
	for _, e := range frame.Events {
		select {
		case s.events <- e:
		case <-s.done:
			return false
		default:
			// Drop oldest if buffer is full rather than blocking.
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

// isExpired reports whether the session has timed out or needs rekeying.
func (s *session) isExpired() bool {
	lastRecv := s.lastRecv.Load().(time.Time)
	return time.Since(lastRecv) > sessionTimeout ||
		time.Since(s.created) > rekeyAfterTime ||
		atomic.LoadUint64(&s.sendCounter) >= rekeyAfterMessages
}

// needsKeepalive reports whether a keepalive packet should be sent.
func (s *session) needsKeepalive() bool {
	lastRecv := s.lastRecv.Load().(time.Time)
	return time.Since(lastRecv) > keepaliveInterval
}
