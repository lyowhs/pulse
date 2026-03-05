package wiresocket

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"golang.org/x/net/ipv4"
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

	// EventBufSize is the number of events buffered per channel on the receive
	// side.  Defaults to max(socketBuf*3/4/MaxPacketSize, defaultReliableWindow),
	// probed from the kernel UDP receive buffer — the same formula used by
	// ServerConfig.  The floor of defaultReliableWindow (4096) is critical:
	// the sender assumes the receiver can absorb that many events before the
	// first ACK arrives; a smaller buffer causes the first burst of coalesced
	// events to overflow and be silently dropped.
	// Override to tune the flow-control window advertised to the remote peer;
	// for example, set it to inflightCap when sending large fragmented events
	// so the server's echo window stays within the socket buffer capacity.
	EventBufSize int

	// HandshakeTimeout is the maximum time to wait for the server to respond
	// to a HandshakeInit.  Defaults to 5 s.
	HandshakeTimeout time.Duration

	// MaxRetries is the number of times to retransmit HandshakeInit before
	// giving up.  Defaults to 5.
	MaxRetries int

	// ReconnectMin, if non-zero, enables automatic reconnection on connection
	// loss.  It is the minimum backoff between reconnect attempts.
	ReconnectMin time.Duration

	// ReconnectMax is the maximum backoff between reconnect attempts.
	// Defaults to 30 s when ReconnectMin is non-zero.
	ReconnectMax time.Duration

	// SessionTimeout is how long a session may be idle before the client
	// tears it down.  Defaults to 180 s.  Each side enforces its own
	// timeout independently, so clients and servers may use different values.
	SessionTimeout time.Duration

	// KeepaliveInterval is how often to send keepalive probes when data is
	// idle.  Defaults to 10 s.  Must be less than the server's SessionTimeout.
	KeepaliveInterval time.Duration

	// MaxIncompleteFrames is the maximum number of partially-reassembled
	// fragmented frames buffered per session.  Excess fragments are dropped.
	// Defaults to 64.
	MaxIncompleteFrames int

	// MaxPacketSize is the maximum UDP payload size in bytes used when
	// fragmenting outgoing frames.  Larger values reduce the number of
	// fragments (and therefore syscalls) per large frame, improving
	// throughput on links that support bigger datagrams.
	// Defaults to 1232 (safe for IPv6 minimum path MTU).
	// Set up to 65000 for loopback or LAN benchmarks (IPv4 hard limit is
	// 65507; leave headroom for safety).
	MaxPacketSize int

	// MaxEventPayloadSize, if non-zero, is the largest event payload the
	// application will send on this connection in bytes.  The library uses it
	// to compute fragsPerEvent and derives EventBufSize, MaxIncompleteFrames,
	// and the default reliable WindowSize accordingly, so that in-flight
	// fragments never exceed the kernel socket-buffer capacity.
	// When zero each event is assumed to fit in a single packet (fragsPerEvent = 1).
	MaxEventPayloadSize int

	// CoalesceInterval, if non-zero, enables event coalescing: events passed
	// to Channel.Send are buffered and sent together as a single encrypted
	// frame after this interval elapses.  This reduces per-event encryption
	// and syscall overhead at the cost of added latency equal to the interval.
	// Typical values: 50µs–1ms.  Zero disables coalescing (default).
	CoalesceInterval time.Duration

	// SendRateLimitBPS, if non-zero, limits the outgoing byte rate to
	// approximately this many bytes per second.  A burst of up to 2× the
	// per-second rate is allowed before throttling begins.  0 means unlimited.
	// Ignored when CongestionControl is non-nil.
	SendRateLimitBPS int64

	// CongestionControl, when non-nil, enables the AIMD congestion controller.
	// The controller starts at a conservative rate, ramps up exponentially
	// (slow start), then adjusts linearly based on retransmit-detected loss.
	// Requires at least one reliable channel on the Conn for loss feedback.
	// Overrides SendRateLimitBPS when set.
	CongestionControl *CongestionConfig

}

func (cfg *DialConfig) defaults() {
	if cfg.HandshakeTimeout == 0 {
		cfg.HandshakeTimeout = 5 * time.Second
	}
	if cfg.MaxRetries == 0 {
		cfg.MaxRetries = 5
	}
	if cfg.ReconnectMin > 0 && cfg.ReconnectMax == 0 {
		cfg.ReconnectMax = 30 * time.Second
	}
	if cfg.SessionTimeout == 0 {
		cfg.SessionTimeout = sessionTimeout
	}
	if cfg.KeepaliveInterval == 0 {
		cfg.KeepaliveInterval = keepaliveInterval
	}
	// MaxPacketSize must be resolved before buffer-derived defaults.
	if cfg.MaxPacketSize == 0 {
		cfg.MaxPacketSize = defaultMaxPacketSize
	}
	// fragsPerEvent: how many UDP packets one event occupies on the wire.
	// Used to scale EventBufSize and MaxIncompleteFrames so that the total
	// number of in-flight fragments never exceeds the socket buffer capacity.
	maxFrag := cfg.MaxPacketSize - sizeDataHeader - sizeFragmentHeader - sizeAEADTag
	fragsPerEvent := 1
	if cfg.MaxEventPayloadSize > 0 && maxFrag > 0 && cfg.MaxEventPayloadSize > maxFrag {
		fragsPerEvent = (cfg.MaxEventPayloadSize + maxFrag - 1) / maxFrag
	}
	// Auto-size MaxIncompleteFrames and EventBufSize from the kernel UDP socket
	// buffer so neither becomes a bottleneck regardless of payload size.
	if cfg.MaxIncompleteFrames == 0 || cfg.EventBufSize == 0 {
		const bufRequest = 4 << 20
		actual := ProbeUDPRecvBufSize(bufRequest)
		ic := actual * 3 / 4 / (fragsPerEvent * cfg.MaxPacketSize)
		if ic < maxReassemblyBufs {
			ic = maxReassemblyBufs
		}
		if cfg.MaxIncompleteFrames == 0 {
			cfg.MaxIncompleteFrames = ic
		}
		if cfg.EventBufSize == 0 {
			cfg.EventBufSize = ic
			// The sender initialises peerWindow = defaultReliableWindow before
			// receiving any ACK, so EventBufSize must be at least that large or
			// the first burst of coalesced events will overflow the buffer.
			if cfg.EventBufSize < defaultReliableWindow {
				cfg.EventBufSize = defaultReliableWindow
			}
		}
	}
}

// Dial connects to a wiresocket server at addr, completes the Noise IK
// handshake, and returns a bidirectional Conn.
//
// addr must be a host:port string resolvable as UDP (e.g. "server.example.com:9000").
//
// If cfg.ReconnectMin is non-zero, the returned Conn automatically reconnects
// after connection loss.  Channel Send and Recv calls block transparently
// while reconnecting.
func Dial(ctx context.Context, addr string, cfg DialConfig) (*Conn, error) {
	cfg.defaults()

	raddr, udpConn, sess, err := dialSession(ctx, addr, cfg)
	if err != nil {
		return nil, err
	}

	if cfg.ReconnectMin > 0 {
		pctx, cancel := context.WithCancel(context.Background())
		ready := make(chan struct{})
		close(ready) // initially connected

		// Default the reliable window to EventBufSize so the send window is
		// automatically bounded by the socket-buffer-derived inflight cap.
		newChannelCfg := ReliableCfg{WindowSize: cfg.EventBufSize}
		// CC requires reliable with enough retries to survive rate-limited sends.
		if cfg.CongestionControl != nil && newChannelCfg.MaxRetries < 30 {
			newChannelCfg.MaxRetries = 30
		}
		c := &Conn{
			addr:          addr,
			dialCfg:       cfg,
			ctx:           pctx,
			cancel:        cancel,
			done:          make(chan struct{}),
			ready:         ready,
			sess:          sess,
			newChannelCfg: newChannelCfg,
		}
		c.ch0 = newChannel(0, c, cfg.EventBufSize)
		c.channelMap.Store(uint16(0), c.ch0)
		if cfg.CoalesceInterval > 0 {
			maxFrag := cfg.MaxPacketSize - sizeDataHeader - sizeFragmentHeader - sizeAEADTag
			c.coalescer = newCoalescer(c, cfg.CoalesceInterval, maxFrag)
		}
		// Create CC before wireSession so wireSession can install it as the
		// session rate limiter on the first (and every subsequent) session.
		if cfg.CongestionControl != nil {
			c.cc = newAIMDController(normalizeCCConfig(*cfg.CongestionControl), c)
		}
		// Wire the router before starting the read loop so sess.router is
		// visible inside the goroutine (goroutine-start happens-before).
		c.wireSession(sess)
		dbg("persistent conn created", "addr", addr, "local_index", sess.localIndex)
		go clientReadLoop(udpConn, sess, raddr)
		go clientKeepaliveLoop(sess)
		go c.reconnectLoop()
		if c.cc != nil {
			go c.cc.run()
		}
		return c, nil
	}

	// Non-persistent: wire the router (inside newConn) before starting the
	// read loop so the goroutine-start happens-before makes it visible.
	newChannelCfg := ReliableCfg{WindowSize: cfg.EventBufSize}
	if cfg.CongestionControl != nil && newChannelCfg.MaxRetries < 30 {
		newChannelCfg.MaxRetries = 30
	}
	conn := newConn(sess, cfg.CoalesceInterval, newChannelCfg)
	if cfg.CongestionControl != nil {
		cc := newAIMDController(normalizeCCConfig(*cfg.CongestionControl), conn)
		conn.cc = cc
		// wireSession already ran inside newConn; install CC on the session directly.
		conn.sess.rateLimiter = cc
		go cc.run()
	}
	go clientReadLoop(udpConn, sess, raddr)
	go clientKeepaliveLoop(sess)
	return conn, nil
}

// dialSession performs a single full handshake and returns the established
// UDP connection, resolved remote address, and new session.  It is called by
// Dial for the initial connection and by reconnectLoop for each reconnect.
func dialSession(ctx context.Context, addr string, cfg DialConfig) (*net.UDPAddr, *net.UDPConn, *session, error) {
	raddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("wiresocket: resolve %q: %w", addr, err)
	}

	conn, err := net.ListenUDP("udp", &net.UDPAddr{})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("wiresocket: listen UDP: %w", err)
	}
	const socketBufSize = 4 << 20 // 4 MiB
	setSocketBuffers(conn, socketBufSize)

	kp, err := resolveClientKeypair(cfg.PrivateKey)
	if err != nil {
		conn.Close()
		return nil, nil, nil, err
	}

	localIdx, err := randUint32()
	if err != nil {
		conn.Close()
		return nil, nil, nil, err
	}

	hs, err := newInitiatorState(kp, cfg.ServerPublicKey)
	if err != nil {
		conn.Close()
		return nil, nil, nil, err
	}

	initMsg, err := hs.CreateInit(localIdx)
	if err != nil {
		conn.Close()
		return nil, nil, nil, err
	}
	initBytes := initMsg.marshal()

	retryDelay := 250 * time.Millisecond
	var cookie [16]byte
	hasCookie := false

	for attempt := 0; attempt < cfg.MaxRetries; attempt++ {
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
			return nil, nil, nil, fmt.Errorf("wiresocket: send HandshakeInit: %w", err)
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
				return nil, nil, nil, ctx.Err()
			default:
			}
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
				continue
			}
			if err := hs.ConsumeResp(resp); err != nil {
				conn.Close()
				return nil, nil, nil, fmt.Errorf("wiresocket: handshake failed: %w", err)
			}
			dbg("client: handshake complete",
				"local_index", localIdx,
				"remote_index", resp.SenderIndex,
			)
			sendKey, recvKey := hs.TransportKeys(true)
			maxFrag := cfg.MaxPacketSize - sizeDataHeader - sizeFragmentHeader - sizeAEADTag
			sess := newSession(localIdx, resp.SenderIndex, sendKey, recvKey, raddr, conn, cfg.EventBufSize, cfg.SessionTimeout, cfg.KeepaliveInterval, cfg.MaxIncompleteFrames, maxFrag, cfg.SendRateLimitBPS)
			return raddr, conn, sess, nil

		case typeCookieReply:
			dbg("client: recv CookieReply, will retry with MAC2")
			cr, err := parseCookieReply(buf[:n])
			if err != nil {
				dbg("client: parse CookieReply failed", "err", err)
				continue
			}
			if cr.ReceiverIndex != localIdx {
				dbg("client: CookieReply receiver_index mismatch",
					"got", cr.ReceiverIndex,
					"want", localIdx,
				)
				continue
			}
			cookie, err = ConsumeCookieReply(cr, initMsg.MAC1)
			if err != nil {
				dbg("client: ConsumeCookieReply failed", "err", err)
				continue
			}
			hasCookie = true
			continue
		}
	}

	dbg("client: handshake timed out after all retries",
		"local_index", localIdx,
		"remote_addr", raddr.String(),
		"max_retries", cfg.MaxRetries,
	)
	conn.Close()
	return nil, nil, nil, errors.New("wiresocket: handshake timed out after retries")
}

// clientReadLoop runs in a background goroutine, reading incoming UDP packets
// and delivering them to the session.  Up to readBatchSz datagrams are read
// per syscall using ipv4.PacketConn.ReadBatch.
func clientReadLoop(conn *net.UDPConn, sess *session, raddr *net.UDPAddr) {
	dbg("client: read loop started", "local_index", sess.localIndex, "remote_addr", raddr.String())

	defer func() {
		dbg("client: read loop stopped", "local_index", sess.localIndex)
		sess.close()
		conn.Close()
	}()

	const batchSz = 16
	pc := ipv4.NewPacketConn(conn)
	msgs := make([]ipv4.Message, batchSz)
	for i := range msgs {
		msgs[i].Buffers = [][]byte{make([]byte, 65535)}
	}
	raddrStr := raddr.String()

	for {
		select {
		case <-sess.done:
			return
		default:
		}

		conn.SetReadDeadline(time.Now().Add(sess.timeout))
		n, err := pc.ReadBatch(msgs, 0)
		conn.SetReadDeadline(time.Time{})

		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				if !sess.isExpired() {
					dbg("client: read timeout (session still alive)", "local_index", sess.localIndex)
					continue
				}
				dbg("client: session expired after read timeout", "local_index", sess.localIndex)
			} else {
				dbg("client: read error", "local_index", sess.localIndex, "err", err)
			}
			return
		}

		for i := 0; i < n; i++ {
			msg := &msgs[i]
			src, _ := msg.Addr.(*net.UDPAddr)
			if msg.N == 0 || src == nil || src.String() != raddrStr {
				msg.N = 0
				continue
			}
			buf := msg.Buffers[0][:msg.N]
			switch buf[0] {
			case typeData:
				sess.receive(buf)
			case typeDataFragment:
				sess.receiveFragment(buf)
			case typeKeepalive:
				sess.receiveKeepalive(buf)
			case typeDisconnect:
				dbg("client: recv disconnect from server", "local_index", sess.localIndex)
				return
			default:
				dbg("client: unknown packet type, dropping", "type", buf[0], "len", msg.N)
			}
			msg.N = 0
		}
	}
}

// clientKeepaliveLoop sends keepalives and enforces the session timeout.
func clientKeepaliveLoop(sess *session) {
	dbg("client: keepalive loop started", "local_index", sess.localIndex)
	ticker := time.NewTicker(sess.keepalive)
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
			if sess.needsKeepalive() {
				sess.sendKeepalive()
			}
			sess.gcFragBufs(sess.keepalive * 2)
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
