package wiresocket

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"
)

// DialConfig configures Dial.
type DialConfig struct {
	// ServerPublicKey is the server's long-term X25519 public key.
	// This must be obtained from the server out-of-band (e.g. config file).
	ServerPublicKey [32]byte

	// PrivateKey is the client's long-term X25519 private key.
	// If zero, a fresh ephemeral key is generated for each Dial call.
	// Providing a stable key enables the server to authenticate the client
	// via its static public key in the Authenticate callback.
	PrivateKey [32]byte

	// EventBufSize is the number of events buffered on the receive side.
	// Defaults to 256.
	EventBufSize int

	// HandshakeTimeout is the maximum time to wait for the server to respond
	// to a HandshakeInit.  Defaults to 5 s.
	HandshakeTimeout time.Duration

	// MaxRetries is the number of times to retransmit HandshakeInit before
	// giving up.  Defaults to 5.
	MaxRetries int
}

func (cfg *DialConfig) defaults() {
	if cfg.EventBufSize == 0 {
		cfg.EventBufSize = 256
	}
	if cfg.HandshakeTimeout == 0 {
		cfg.HandshakeTimeout = 5 * time.Second
	}
	if cfg.MaxRetries == 0 {
		cfg.MaxRetries = 5
	}
}

// Dial connects to a wiresocket server at addr, completes the Noise IK
// handshake, and returns a bidirectional Conn.
//
// addr must be a host:port string resolvable as UDP (e.g. "server.example.com:9000").
func Dial(ctx context.Context, addr string, cfg DialConfig) (*Conn, error) {
	cfg.defaults()

	// Resolve remote address.
	raddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("wiresocket: resolve %q: %w", addr, err)
	}

	// Bind a local UDP port (OS-assigned).
	conn, err := net.ListenUDP("udp", &net.UDPAddr{})
	if err != nil {
		return nil, fmt.Errorf("wiresocket: listen UDP: %w", err)
	}

	kp, err := resolveClientKeypair(cfg.PrivateKey)
	if err != nil {
		conn.Close()
		return nil, err
	}

	// Pick a random sender index.
	localIdx, err := randUint32()
	if err != nil {
		conn.Close()
		return nil, err
	}

	hs, err := newInitiatorState(kp, cfg.ServerPublicKey)
	if err != nil {
		conn.Close()
		return nil, err
	}

	initMsg, err := hs.CreateInit(localIdx)
	if err != nil {
		conn.Close()
		return nil, err
	}
	initBytes := initMsg.marshal()

	// Retry loop: send HandshakeInit and wait for HandshakeResp or CookieReply.
	retryDelay := 250 * time.Millisecond
	var cookie [16]byte
	hasCookie := false

	for attempt := 0; attempt < cfg.MaxRetries; attempt++ {
		// Stamp MAC2 if we have a cookie from a previous CookieReply.
		if hasCookie {
			mac2 := computeMAC2(cookie, initMsg.mac1Body())
			copy(initBytes[132:148], mac2[:])
		}

		dbg("client: sending HandshakeInit",
			"attempt", attempt+1,
			"max_retries", cfg.MaxRetries,
			"local_index", localIdx,
			"remote_addr", raddr.String(),
			"has_cookie", hasCookie,
		)
		if _, err := conn.WriteToUDP(initBytes, raddr); err != nil {
			conn.Close()
			return nil, fmt.Errorf("wiresocket: send HandshakeInit: %w", err)
		}

		deadline := time.Now().Add(cfg.HandshakeTimeout)
		if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
			deadline = ctxDeadline
		}
		conn.SetReadDeadline(deadline)

		buf := make([]byte, 65535)
		n, src, err := conn.ReadFromUDP(buf)
		conn.SetReadDeadline(time.Time{}) // clear deadline

		if err != nil {
			select {
			case <-ctx.Done():
				conn.Close()
				return nil, ctx.Err()
			default:
			}
			// Timeout — retry.
			dbg("client: HandshakeInit timed out, retrying",
				"attempt", attempt+1,
				"retry_delay", retryDelay,
			)
			time.Sleep(retryDelay)
			retryDelay *= 2
			continue
		}

		if n == 0 || src.String() != raddr.String() {
			continue
		}

		switch buf[0] {
		case typeHandshakeResp:
			dbg("client: recv HandshakeResp", "remote_addr", src.String())
			resp, err := parseHandshakeResp(buf[:n])
			if err != nil {
				dbg("client: parse HandshakeResp failed", "err", err)
				continue
			}
			if resp.ReceiverIndex != localIdx {
				dbg("client: HandshakeResp receiver_index mismatch",
					"got", resp.ReceiverIndex,
					"want", localIdx,
				)
				continue // not for us
			}
			if err := hs.ConsumeResp(resp); err != nil {
				conn.Close()
				return nil, fmt.Errorf("wiresocket: handshake failed: %w", err)
			}
			dbg("client: handshake complete",
				"local_index", localIdx,
				"remote_index", resp.SenderIndex,
			)
			sendKey, recvKey := hs.TransportKeys(true) // true = initiator
			sess := newSession(localIdx, resp.SenderIndex, sendKey, recvKey, raddr, conn, cfg.EventBufSize)

			// Start background goroutines for the client conn.
			go clientReadLoop(conn, sess, raddr)
			go clientKeepaliveLoop(sess)

			return newConn(sess), nil

		case typeCookieReply:
			dbg("client: recv CookieReply, will retry with MAC2")
			cr, err := parseCookieReply(buf[:n])
			if err != nil {
				continue
			}
			if cr.ReceiverIndex != localIdx {
				continue
			}
			cookie, err = ConsumeCookieReply(cr, initMsg.MAC1)
			if err != nil {
				continue
			}
			hasCookie = true
			// Retry immediately with mac2 set.
			continue
		}
	}

	conn.Close()
	return nil, errors.New("wiresocket: handshake timed out after retries")
}

// clientReadLoop runs in a background goroutine, reading incoming UDP packets
// and delivering them to the session.
func clientReadLoop(conn *net.UDPConn, sess *session, raddr *net.UDPAddr) {
	dbg("client: read loop started", "local_index", sess.localIndex, "remote_addr", raddr.String())
	defer func() {
		dbg("client: read loop stopped", "local_index", sess.localIndex)
		sess.close()
		conn.Close()
	}()

	buf := make([]byte, 65535)
	for {
		select {
		case <-sess.done:
			return
		default:
		}

		conn.SetReadDeadline(time.Now().Add(keepaliveInterval * 2))
		n, src, err := conn.ReadFromUDP(buf)
		conn.SetReadDeadline(time.Time{})

		if err != nil {
			// A read timeout just means no packet arrived in the window —
			// the session may still be healthy.  Check expiry and loop back.
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				if !sess.isExpired() {
					dbg("client: read timeout (session still alive)", "local_index", sess.localIndex)
					continue
				}
				dbg("client: session expired after read timeout", "local_index", sess.localIndex)
				// Session has timed out — fall through to close.
			} else {
				dbg("client: read error", "local_index", sess.localIndex, "err", err)
			}
			// Real network error or expired session — terminate.
			return
		}
		if n == 0 || src.String() != raddr.String() {
			continue
		}
		if buf[0] == typeData {
			sess.receive(buf[:n])
		}
	}
}

// clientKeepaliveLoop sends keepalives and enforces the session timeout.
func clientKeepaliveLoop(sess *session) {
	dbg("client: keepalive loop started", "local_index", sess.localIndex)
	ticker := time.NewTicker(keepaliveInterval)
	defer ticker.Stop()
	for {
		select {
		case <-sess.done:
			dbg("client: keepalive loop stopped", "local_index", sess.localIndex)
			return
		case <-ticker.C:
			if sess.isExpired() {
				dbg("client: session expired, closing", "local_index", sess.localIndex)
				sess.close()
				return
			}
			sess.sendKeepalive()
		}
	}
}

// resolveClientKeypair returns a Keypair from the given private key bytes, or
// generates a fresh one if priv is all zeros.
func resolveClientKeypair(priv [32]byte) (Keypair, error) {
	var zero [32]byte
	if priv == zero {
		return GenerateKeypair()
	}
	pub, err := pubFromPriv(priv)
	if err != nil {
		return Keypair{}, err
	}
	return Keypair{Private: priv, Public: pub}, nil
}
