// Package wiresocket implements a secure, bidirectional event-stream protocol
// over UDP, designed to serve 10,000s of simultaneous clients.
//
// # Protocol
//
// The wire protocol is inspired by WireGuard and uses the Noise IK handshake
// pattern (Noise_IK_25519_ChaChaPoly_BLAKE2s) for authenticated key exchange,
// ChaCha20-Poly1305 for data encryption, and BLAKE2s for hashing and MACs.
// Application messages are binary-encoded Protocol Buffer Frames containing
// one or more Events.
//
// # Handshake
//
// Before exchanging application data the initiator (client) and responder
// (server) complete a two-message Noise IK handshake:
//
//	Client                                  Server
//	──────                                  ──────
//	HandshakeInit  ──────────────────────►
//	               ◄──────────────────────  HandshakeResp
//	[session established — data flows in both directions]
//
// The server's static public key must be distributed to clients out-of-band.
// The client's static key is transmitted (encrypted) during the handshake,
// allowing the server to authenticate clients via the Authenticate callback.
//
// # DoS Mitigation
//
// Under load the server may respond with a CookieReply instead of
// HandshakeResp.  The client retries with the cookie embedded in MAC2, proving
// IP-address ownership without maintaining per-client state on the server.
//
// # Replay Protection
//
// Each session maintains a 64-entry sliding-window counter (identical to
// WireGuard's).  Packets with a counter that has already been seen or that
// falls outside the window are dropped.
//
// # Scalability
//
// The server uses a single UDP socket and a fixed-size worker pool
// (defaulting to GOMAXPROCS) for packet decryption.  Sessions are stored in a
// sync.Map keyed by a 32-bit session index, giving O(1) lookup on the hot
// path.  A background goroutine periodically evicts expired sessions.
//
// # Usage
//
//	// Server
//	kp, _ := wiresocket.GenerateKeypair()
//	srv, _ := wiresocket.NewServer(wiresocket.ServerConfig{
//	    Addr:       ":9000",
//	    PrivateKey: kp.Private,
//	    OnConnect: func(conn *wiresocket.Conn) {
//	        for {
//	            e, err := conn.Recv(context.Background())
//	            if err != nil { return }
//	            conn.Send(context.Background(), &proto.Event{
//	                Type: "pong", Payload: e.Payload,
//	            })
//	        }
//	    },
//	})
//	srv.Serve(context.Background())
//
//	// Client
//	conn, _ := wiresocket.Dial(context.Background(), "server:9000", wiresocket.DialConfig{
//	    ServerPublicKey: kp.Public,
//	})
//	conn.Send(ctx, &proto.Event{Type: "ping", Payload: []byte("hello")})
//	e, _ := conn.Recv(ctx)
//	fmt.Println(string(e.Payload)) // "hello"
//	conn.Close()
package wiresocket
