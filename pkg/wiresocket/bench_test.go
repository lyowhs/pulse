package wiresocket_test

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"example.com/pulse/pulse/pkg/wiresocket"
)

// BenchmarkThroughput measures round-trip throughput (send + echo) for
// various payload sizes using loopback UDP with MaxPacketSize=65000.
// Run with:
//
//	go test ./pkg/wiresocket/ -bench=BenchmarkThroughput -benchtime=5s -v
func BenchmarkThroughput(b *testing.B) {
	for _, size := range []int{1 << 10, 64 << 10, 512 << 10} {
		b.Run(fmt.Sprintf("%dKB", size>>10), func(b *testing.B) {
			benchThroughput(b, size, 65000)
		})
	}
}

// BenchmarkThroughputStdMTU measures round-trip throughput for the same
// payload sizes as BenchmarkThroughput but with MaxPacketSize=1472, the
// largest UDP payload that fits inside a standard 1500-byte Ethernet frame
// (1500 − 20-byte IPv4 header − 8-byte UDP header).  This reflects real
// internet conditions where jumbo frames are not available.
// Run with:
//
//	go test ./pkg/wiresocket/ -bench=BenchmarkThroughputStdMTU -benchtime=5s -v
func BenchmarkThroughputStdMTU(b *testing.B) {
	// 512 KB is excluded: at MTU=1472, maxFragPayload=1434 bytes, so a 512 KB
	// frame requires ceil(524288/1434) = 366 fragments which exceeds the
	// 255-fragment protocol limit.  1 KB and 64 KB fit comfortably.
	for _, size := range []int{1 << 10, 64 << 10} {
		b.Run(fmt.Sprintf("%dKB", size>>10), func(b *testing.B) {
			benchThroughput(b, size, 1472)
		})
	}
}

func benchThroughput(b *testing.B, payloadSize, maxPacketSize int) {
	b.Helper()
	b.ReportAllocs()

	addr, kp := startBenchServer(b, maxPacketSize)

	conn, err := wiresocket.Dial(context.Background(), addr, wiresocket.DialConfig{
		ServerPublicKey:  kp.Public,
		HandshakeTimeout: 5 * time.Second,
		MaxRetries:       10,
		MaxPacketSize:    maxPacketSize,
	})
	if err != nil {
		b.Fatalf("Dial: %v", err)
	}
	b.Cleanup(func() { conn.Close() })

	ch := conn.Channel(1)
	payload := make([]byte, payloadSize)

	b.SetBytes(int64(payloadSize))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if err := ch.Send(context.Background(), &wiresocket.Event{Type: 1, Payload: payload}); err != nil {
			b.Fatalf("Send: %v", err)
		}
		if _, err := ch.Recv(context.Background()); err != nil {
			b.Fatalf("Recv: %v", err)
		}
	}
}

// startBenchServer binds an in-process echo server on a free loopback port
// and returns its address and keypair.  The server is stopped when the test
// ends via b.Cleanup.
func startBenchServer(b *testing.B, maxPacketSize int) (addr string, kp wiresocket.Keypair) {
	b.Helper()

	kp, err := wiresocket.GenerateKeypair()
	if err != nil {
		b.Fatalf("GenerateKeypair: %v", err)
	}

	port := freeUDPPort(b)
	addr = fmt.Sprintf("127.0.0.1:%d", port)

	srv, err := wiresocket.NewServer(wiresocket.ServerConfig{
		Addr:       addr,
		PrivateKey: kp.Private,
		OnConnect: func(conn *wiresocket.Conn) {
			ch := conn.Channel(1)
			for {
				e, err := ch.Recv(context.Background())
				if err != nil {
					return
				}
				if err := ch.Send(context.Background(), e); err != nil {
					return
				}
			}
		},
		MaxPacketSize: maxPacketSize,
	})
	if err != nil {
		b.Fatalf("NewServer: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	b.Cleanup(cancel)

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(ctx) }()

	// Wait for the server socket to be ready.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("udp", addr, 100*time.Millisecond)
		if err == nil {
			c.Close()
			return addr, kp
		}
		time.Sleep(5 * time.Millisecond)
	}
	b.Fatal("server did not start within 2 s")
	return
}

// freeUDPPort returns an available local UDP port.
func freeUDPPort(b *testing.B) int {
	b.Helper()
	l, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		b.Fatalf("freeUDPPort: %v", err)
	}
	port := l.LocalAddr().(*net.UDPAddr).Port
	l.Close()
	return port
}

// ─── frame encoding benchmarks ───────────────────────────────────────────────

// BenchmarkFrameMarshal measures the CPU and allocation cost of encoding a
// Frame into its wire format for varying numbers of events per frame.
// Run with:
//
//	go test ./pkg/wiresocket/ -bench=BenchmarkFrameMarshal -benchmem
func BenchmarkFrameMarshal(b *testing.B) {
	for _, n := range []int{1, 4, 16} {
		b.Run(fmt.Sprintf("%dEvents", n), func(b *testing.B) {
			b.ReportAllocs()
			events := make([]*wiresocket.Event, n)
			for i := range events {
				events[i] = &wiresocket.Event{
					Type:    uint8(i + 1),
					Payload: make([]byte, 64),
				}
			}
			f := &wiresocket.Frame{
				ChannelId:  1,
				Events:     events,
				Seq:        42,
				AckSeq:     41,
				WindowSize: 256,
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = f.Marshal()
			}
		})
	}
}

// BenchmarkFrameMarshalReuse measures Frame encoding when the caller reuses a
// pre-allocated destination buffer (the AppendMarshal zero-allocation path).
func BenchmarkFrameMarshalReuse(b *testing.B) {
	b.ReportAllocs()
	events := make([]*wiresocket.Event, 8)
	for i := range events {
		events[i] = &wiresocket.Event{Type: uint8(i + 1), Payload: make([]byte, 64)}
	}
	f := &wiresocket.Frame{ChannelId: 1, Events: events, Seq: 100}
	dst := make([]byte, 0, 1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dst = f.AppendMarshal(dst[:0])
	}
	_ = dst
}

// BenchmarkFrameUnmarshal measures the CPU and allocation cost of decoding a
// Frame from its wire format for varying numbers of events per frame.
// Run with:
//
//	go test ./pkg/wiresocket/ -bench=BenchmarkFrameUnmarshal -benchmem
func BenchmarkFrameUnmarshal(b *testing.B) {
	for _, n := range []int{1, 4, 16} {
		b.Run(fmt.Sprintf("%dEvents", n), func(b *testing.B) {
			b.ReportAllocs()
			events := make([]*wiresocket.Event, n)
			for i := range events {
				events[i] = &wiresocket.Event{
					Type:    uint8(i + 1),
					Payload: make([]byte, 64),
				}
			}
			wire := (&wiresocket.Frame{
				ChannelId:  7,
				Events:     events,
				Seq:        99,
				AckSeq:     98,
				WindowSize: 512,
			}).Marshal()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := wiresocket.UnmarshalFrame(wire); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// ─── handshake benchmark ─────────────────────────────────────────────────────

// BenchmarkHandshakeDial measures the wall-clock and allocation cost of a
// complete Noise IK handshake (Dial + Close) on loopback.
// Run with:
//
//	go test ./pkg/wiresocket/ -bench=BenchmarkHandshakeDial -benchmem -benchtime=20s
func BenchmarkHandshakeDial(b *testing.B) {
	b.ReportAllocs()
	addr, kp := startBenchServer(b, 65000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn, err := wiresocket.Dial(context.Background(), addr, wiresocket.DialConfig{
			ServerPublicKey:  kp.Public,
			HandshakeTimeout: 5 * time.Second,
			MaxRetries:       5,
			MaxPacketSize:    65000,
		})
		if err != nil {
			b.Fatalf("Dial: %v", err)
		}
		conn.Close()
	}
}

// ─── unreliable channel benchmarks ───────────────────────────────────────────

// BenchmarkSendRecvUnreliable measures round-trip throughput on an unreliable
// channel (no ACKs, no retransmit overhead) for various payload sizes.
// Compare with BenchmarkThroughput to see the overhead of reliable delivery.
// Run with:
//
//	go test ./pkg/wiresocket/ -bench=BenchmarkSendRecvUnreliable -benchmem -benchtime=5s
func BenchmarkSendRecvUnreliable(b *testing.B) {
	for _, size := range []int{64, 1 << 10, 64 << 10} {
		b.Run(fmt.Sprintf("%dB", size), func(b *testing.B) {
			benchSendRecvUnreliable(b, size, 65000)
		})
	}
}

func benchSendRecvUnreliable(b *testing.B, payloadSize, maxPacketSize int) {
	b.Helper()
	b.ReportAllocs()

	addr, kp := startBenchServerUnreliable(b, maxPacketSize)

	conn, err := wiresocket.Dial(context.Background(), addr, wiresocket.DialConfig{
		ServerPublicKey:  kp.Public,
		HandshakeTimeout: 5 * time.Second,
		MaxRetries:       10,
		MaxPacketSize:    maxPacketSize,
	})
	if err != nil {
		b.Fatalf("Dial: %v", err)
	}
	b.Cleanup(func() { conn.Close() })

	ch := conn.Channel(1)
	ch.SetUnreliable()
	payload := make([]byte, payloadSize)

	b.SetBytes(int64(payloadSize))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if err := ch.Send(context.Background(), &wiresocket.Event{Type: 1, Payload: payload}); err != nil {
			b.Fatalf("Send: %v", err)
		}
		if _, err := ch.Recv(context.Background()); err != nil {
			b.Fatalf("Recv: %v", err)
		}
	}
}

// startBenchServerUnreliable starts an echo server whose handler uses
// unreliable channels, so neither side tracks sequence numbers or ACKs.
func startBenchServerUnreliable(b *testing.B, maxPacketSize int) (addr string, kp wiresocket.Keypair) {
	b.Helper()

	kp, err := wiresocket.GenerateKeypair()
	if err != nil {
		b.Fatalf("GenerateKeypair: %v", err)
	}

	port := freeUDPPort(b)
	addr = fmt.Sprintf("127.0.0.1:%d", port)

	srv, err := wiresocket.NewServer(wiresocket.ServerConfig{
		Addr:          addr,
		PrivateKey:    kp.Private,
		MaxPacketSize: maxPacketSize,
		OnConnect: func(conn *wiresocket.Conn) {
			ch := conn.Channel(1)
			ch.SetUnreliable()
			for {
				e, err := ch.Recv(context.Background())
				if err != nil {
					return
				}
				if err := ch.Send(context.Background(), e); err != nil {
					return
				}
			}
		},
	})
	if err != nil {
		b.Fatalf("NewServer: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	b.Cleanup(cancel)
	go srv.Serve(ctx)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("udp", addr, 100*time.Millisecond)
		if err == nil {
			c.Close()
			return addr, kp
		}
		time.Sleep(5 * time.Millisecond)
	}
	b.Fatal("unreliable server did not start within 2 s")
	return
}

// ─── coalescing benchmark ─────────────────────────────────────────────────────

// BenchmarkSendRecvCoalesced measures round-trip throughput when the client
// uses a coalescer to batch small events.  With rapid b.N iterations, multiple
// events are packed into each UDP frame, amortising per-packet crypto overhead.
// Run with:
//
//	go test ./pkg/wiresocket/ -bench=BenchmarkSendRecvCoalesced -benchmem -benchtime=5s
func BenchmarkSendRecvCoalesced(b *testing.B) {
	for _, size := range []int{32, 256, 1 << 10} {
		b.Run(fmt.Sprintf("%dB", size), func(b *testing.B) {
			benchSendRecvCoalesced(b, size, 65000)
		})
	}
}

func benchSendRecvCoalesced(b *testing.B, payloadSize, maxPacketSize int) {
	b.Helper()
	b.ReportAllocs()

	addr, kp := startBenchServer(b, maxPacketSize)

	conn, err := wiresocket.Dial(context.Background(), addr, wiresocket.DialConfig{
		ServerPublicKey:  kp.Public,
		HandshakeTimeout: 5 * time.Second,
		MaxRetries:       10,
		MaxPacketSize:    maxPacketSize,
		CoalesceInterval: 200 * time.Microsecond,
	})
	if err != nil {
		b.Fatalf("Dial: %v", err)
	}
	b.Cleanup(func() { conn.Close() })

	ch := conn.Channel(1)
	payload := make([]byte, payloadSize)

	b.SetBytes(int64(payloadSize))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if err := ch.Send(context.Background(), &wiresocket.Event{Type: 1, Payload: payload}); err != nil {
			b.Fatalf("Send: %v", err)
		}
		if _, err := ch.Recv(context.Background()); err != nil {
			b.Fatalf("Recv: %v", err)
		}
	}
}
