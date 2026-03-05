package wiresocket_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"example.com/pulse/pulse/pkg/wiresocket"
)

// TestRateLimitDelivery verifies that a rate-limited connection still delivers
// all data correctly (correctness, not timing).
func TestRateLimitDelivery(t *testing.T) {
	const N = 20
	const bps int64 = 10 << 20 // 10 MB/s — high enough that test stays fast

	var received atomic.Int64

	addr, kp := serverSetup(t, wiresocket.ServerConfig{
		SendRateLimitBPS: bps,
		OnConnect: func(conn *wiresocket.Conn) {
			for {
				e, err := conn.Recv(context.Background())
				if err != nil {
					return
				}
				received.Add(1)
				conn.Send(context.Background(), e) // echo
			}
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn := mustDial(t, ctx, addr, kp, wiresocket.DialConfig{
		SendRateLimitBPS: bps,
	})

	payload := make([]byte, 1024)
	for i := 0; i < N; i++ {
		if err := conn.Send(ctx, &wiresocket.Event{Type: 1, Payload: payload}); err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Recv(ctx); err != nil {
			t.Fatal(err)
		}
	}

	if got := received.Load(); got != int64(N) {
		t.Errorf("server received %d events, want %d", got, N)
	}
}

// TestRateLimitTiming verifies that a tight rate limit actually slows down
// sends.  This test is skipped in -short mode because it deliberately takes
// over a second.
func TestRateLimitTiming(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping timing-sensitive test in -short mode")
	}

	// 50 KB/s with burst = 100 KB.
	// Send 40 events × 5 KB = 200 KB total.
	// First 100 KB (20 events) drain the burst instantly.
	// Remaining 100 KB takes ≥ 2 s at 50 KB/s.
	const bps int64 = 50_000
	const payloadSize = 5_000
	const N = 40

	addr, kp := serverSetup(t, wiresocket.ServerConfig{
		OnConnect: func(conn *wiresocket.Conn) { <-conn.Done() },
	})

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn := mustDial(t, ctx, addr, kp, wiresocket.DialConfig{
		SendRateLimitBPS: bps,
	})

	payload := make([]byte, payloadSize)
	start := time.Now()
	for i := 0; i < N; i++ {
		if err := conn.Send(ctx, &wiresocket.Event{Type: 1, Payload: payload}); err != nil {
			t.Fatal(err)
		}
	}
	elapsed := time.Since(start)

	// After the 100 KB burst, the remaining 100 KB must take ≥ 1.5 s.
	const wantMin = 1500 * time.Millisecond
	if elapsed < wantMin {
		t.Errorf("elapsed %v < %v: rate limiting does not appear to be working", elapsed, wantMin)
	}
}
