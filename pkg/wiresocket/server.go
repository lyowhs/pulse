package wiresocket

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// ServerConfig configures a UDP stream server.
type ServerConfig struct {
	// Addr is the UDP address to listen on, e.g. ":9000".
	Addr string

	// PrivateKey is the server's long-term X25519 private key.
	// The corresponding public key is shared with clients out-of-band.
	PrivateKey [32]byte

	// OnConnect is called in a new goroutine for every successfully
	// authenticated peer session.  The Conn is fully established when
	// OnConnect is called; closing it ends the session.
	OnConnect func(conn *Conn)

	// Authenticate, if non-nil, is called with the client's static public
	// key after the handshake.  Return false to reject the client.
	// If nil, all clients are accepted.
	Authenticate func(clientPub [32]byte) bool

	// EventBufSize is the number of events buffered per session.
	// Defaults to 256.
	EventBufSize int

	// WorkerCount is the number of concurrent packet-processing goroutines.
	// Defaults to GOMAXPROCS.
	WorkerCount int

	// UnderLoad, if set, returns true when the server is under DoS stress and
	// should respond with CookieReply instead of processing handshakes.
	UnderLoad func() bool
}

func (cfg *ServerConfig) defaults() {
	if cfg.EventBufSize == 0 {
		cfg.EventBufSize = 256
	}
	if cfg.WorkerCount == 0 {
		cfg.WorkerCount = runtime.GOMAXPROCS(0)
	}
}

// Server is a UDP stream server.  Create one with NewServer and call Serve.
type Server struct {
	cfg     ServerConfig
	keypair Keypair
	cookies *cookieManager

	conn *net.UDPConn

	// sessions maps a server-assigned local index → *session for routing data
	// packets.  Key type: uint32, value type: *session.
	sessions sync.Map

	// pendingHandshakes maps a client's sender_index (uint32) → *noiseState
	// during the brief window between receiving a HandshakeInit and sending
	// the HandshakeResp.
	pending sync.Map

	work chan incomingPacket

	// totalSessions counts active sessions for monitoring.
	totalSessions atomic.Int64
}

type incomingPacket struct {
	data []byte
	addr *net.UDPAddr
}

// NewServer creates a Server from cfg.  Call Serve to start it.
func NewServer(cfg ServerConfig) (*Server, error) {
	cfg.defaults()

	pub, err := pubFromPriv(cfg.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("wiresocket: derive public key: %w", err)
	}
	kp := Keypair{Private: cfg.PrivateKey, Public: pub}

	s := &Server{
		cfg:     cfg,
		keypair: kp,
		cookies: newCookieManager(kp.Public),
		work:    make(chan incomingPacket, cfg.WorkerCount*64),
	}
	return s, nil
}

// PublicKey returns the server's static public key.  Distribute this to
// clients out-of-band (e.g. in configuration files).
func (s *Server) PublicKey() [32]byte {
	return s.keypair.Public
}

// Serve binds the UDP socket and runs the server until ctx is cancelled.
// It returns a non-nil error only if the socket cannot be bound.
func (s *Server) Serve(ctx context.Context) error {
	addr, err := net.ResolveUDPAddr("udp", s.cfg.Addr)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	s.conn = conn

	// Worker goroutines for packet processing.
	var wg sync.WaitGroup
	for i := 0; i < s.cfg.WorkerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.worker(ctx)
		}()
	}

	// Session GC goroutine.
	go s.gc(ctx)

	// UDP read loop (single goroutine, lock-free dispatch).
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				select {
				case <-ctx.Done():
				default:
					// Transient error — continue.
				}
				return
			}
			pkt := incomingPacket{
				data: append([]byte(nil), buf[:n]...),
				addr: addr,
			}
			select {
			case s.work <- pkt:
			default:
				// Worker queue full — drop packet (caller will retransmit).
				dbg("server: worker queue full, dropping packet", "remote_addr", addr.String())
			}
		}
	}()

	<-ctx.Done()
	conn.Close()
	close(s.work)
	wg.Wait()
	return nil
}

// worker processes packets from the work channel.
func (s *Server) worker(ctx context.Context) {
	for {
		select {
		case pkt, ok := <-s.work:
			if !ok {
				return
			}
			s.handlePacket(ctx, pkt)
		case <-ctx.Done():
			return
		}
	}
}

func (s *Server) handlePacket(ctx context.Context, pkt incomingPacket) {
	if len(pkt.data) == 0 {
		return
	}
	switch pkt.data[0] {
	case typeHandshakeInit:
		s.handleHandshakeInit(ctx, pkt)
	case typeData:
		s.handleData(pkt)
	case typeCookieReply:
		// Servers don't receive cookie replies.
	}
}

func (s *Server) handleHandshakeInit(ctx context.Context, pkt incomingPacket) {
	dbg("server: recv HandshakeInit", "remote_addr", pkt.addr.String())
	msg, err := parseHandshakeInit(pkt.data)
	if err != nil {
		dbg("server: parse HandshakeInit failed", "err", err)
		return
	}

	// If under load, send a CookieReply and skip processing.
	if s.cfg.UnderLoad != nil && s.cfg.UnderLoad() {
		dbg("server: under load, sending CookieReply", "remote_addr", pkt.addr.String())
		reply, err := s.cookies.BuildCookieReply(msg.SenderIndex, msg.MAC1, pkt.addr.String())
		if err != nil {
			return
		}
		s.conn.WriteToUDP(reply.marshal(), pkt.addr)
		return
	}

	hs, err := newResponderState(s.keypair)
	if err != nil {
		return
	}
	clientPub, err := hs.ConsumeInit(msg)
	if err != nil {
		dbg("server: ConsumeInit failed", "remote_addr", pkt.addr.String(), "err", err)
		return // MAC1 or crypto failure — drop silently
	}

	// Optional authentication callback.
	if s.cfg.Authenticate != nil && !s.cfg.Authenticate(clientPub) {
		dbg("server: client rejected by Authenticate callback", "remote_addr", pkt.addr.String())
		return
	}

	// Assign a random local index for this session.
	localIdx, err := randUint32()
	if err != nil {
		return
	}
	// Retry on collision (extremely rare).
	for i := 0; i < 8; i++ {
		if _, exists := s.sessions.Load(localIdx); !exists {
			break
		}
		localIdx, err = randUint32()
		if err != nil {
			return
		}
	}

	resp, err := hs.CreateResp(localIdx, msg.SenderIndex)
	if err != nil {
		return
	}

	sendKey, recvKey := hs.TransportKeys(false) // false = responder
	sess := newSession(localIdx, msg.SenderIndex, sendKey, recvKey, pkt.addr, s.conn, s.cfg.EventBufSize)

	s.sessions.Store(localIdx, sess)
	s.totalSessions.Add(1)

	// Send the response.
	s.conn.WriteToUDP(resp.marshal(), pkt.addr)
	dbg("server: sent HandshakeResp",
		"remote_addr", pkt.addr.String(),
		"local_index", localIdx,
		"remote_index", msg.SenderIndex,
	)

	// Hand the conn to the application.
	if s.cfg.OnConnect != nil {
		conn := newConn(sess)
		go func() {
			defer func() {
				dbg("server: session ended",
					"local_index", localIdx,
					"remote_addr", pkt.addr.String(),
				)
				sess.close()
				s.sessions.Delete(localIdx)
				s.totalSessions.Add(-1)
			}()
			s.cfg.OnConnect(conn)
		}()
	}
}

func (s *Server) handleData(pkt incomingPacket) {
	if len(pkt.data) < sizeDataHeader {
		dbg("server: data packet too short", "len", len(pkt.data))
		return
	}
	idx := parseReceiverIndex(pkt.data)
	val, ok := s.sessions.Load(idx)
	if !ok {
		dbg("server: data packet for unknown session", "receiver_index", idx)
		return
	}
	sess := val.(*session)
	if sess.isDone() {
		dbg("server: data packet for closed session", "receiver_index", idx)
		s.sessions.Delete(idx)
		return
	}
	sess.receive(pkt.data)
}

// gc periodically removes expired sessions and sends keepalives.
func (s *Server) gc(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.sessions.Range(func(k, v any) bool {
				sess := v.(*session)
				if sess.isDone() || sess.isExpired() {
					dbg("server: gc evicting session",
						"local_index", sess.localIndex,
						"remote_addr", sess.remoteAddr.String(),
						"expired", sess.isExpired(),
					)
					sess.close()
					s.sessions.Delete(k)
					s.totalSessions.Add(-1)
					return true
				}
				if sess.needsKeepalive() {
					sess.sendKeepalive()
				}
				return true
			})
		}
	}
}

// ActiveSessions returns the current number of established sessions.
func (s *Server) ActiveSessions() int64 {
	return s.totalSessions.Load()
}

// ─── helpers ─────────────────────────────────────────────────────────────────

// parseReceiverIndex reads the receiver_index from a data-packet header
// without allocating.
func parseReceiverIndex(b []byte) uint32 {
	// DataHeader layout: [type(1)][reserved(3)][receiver_index(4)]
	if len(b) < 8 {
		return 0
	}
	return uint32(b[4]) | uint32(b[5])<<8 | uint32(b[6])<<16 | uint32(b[7])<<24
}

// pubFromPriv derives the X25519 public key from a private key.
func pubFromPriv(priv [32]byte) ([32]byte, error) {
	out, err := curveBaseMult(priv)
	if err != nil {
		return [32]byte{}, err
	}
	return out, nil
}

func curveBaseMult(priv [32]byte) ([32]byte, error) {
	kp := Keypair{Private: priv}
	// Clamp.
	kp.Private[0] &= 248
	kp.Private[31] = (kp.Private[31] & 127) | 64
	pub, err := dh(kp.Private, basePoint())
	return pub, err
}

// basePoint returns the X25519 generator point (9 with the rest zeros).
func basePoint() [32]byte {
	var p [32]byte
	p[0] = 9
	return p
}

var errServerClosed = errors.New("wiresocket: server closed")
