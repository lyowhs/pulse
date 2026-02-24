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
