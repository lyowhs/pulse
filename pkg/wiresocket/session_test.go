package wiresocket_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"example.com/pulse/pulse/pkg/wiresocket"
)

// TestLargeFragmentedEvent sends a 64 KiB event at standard MTU (1472 bytes),
// forcing the fragmentation and reassembly path, and verifies the payload
// arrives intact.
func TestLargeFragmentedEvent(t *testing.T) {
	const payloadSize = 64 << 10 // 64 KiB
	const mtu = 1472

	received := make(chan []byte, 1)

	addr, kp := serverSetup(t, wiresocket.ServerConfig{
		MaxPacketSize:       mtu,
		MaxIncompleteFrames: 256,
		WorkChannelSize:     8192,
		OnConnect: func(conn *wiresocket.Conn) {
			e, err := conn.Recv(context.Background())
			if err != nil {
				return
			}
			received <- e.Payload
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn := mustDial(t, ctx, addr, kp, wiresocket.DialConfig{
		MaxPacketSize:       mtu,
		MaxIncompleteFrames: 256,
	})

	payload := make([]byte, payloadSize)
	for i := range payload {
		payload[i] = byte(i & 0xFF)
	}
	if err := conn.Send(ctx, &wiresocket.Event{Type: 7, Payload: payload}); err != nil {
		t.Fatal(err)
	}

	select {
	case got := <-received:
		if len(got) != payloadSize {
			t.Fatalf("payload length: got %d, want %d", len(got), payloadSize)
		}
		for i, b := range got {
			if b != byte(i&0xFF) {
				t.Errorf("payload[%d]: got %d, want %d", i, b, byte(i&0xFF))
				break
			}
		}
	case <-ctx.Done():
		t.Error("timeout: did not receive fragmented event")
	}
}

// TestReassemblyBufferOverflowServerStable verifies that when the per-session
// reassembly table is full (MaxIncompleteFrames reached), excess fragmented
// frames are silently dropped without crashing or deadlocking the server.
// After the burst the server must still be usable — demonstrated by a final
// small reliable event on the default channel completing successfully.
//
// Setup:
//   - MaxPacketSize=200 forces fragmentation (maxFrag=160 B; a 300-byte event
//     splits into 2 fragments).
//   - MaxIncompleteFrames=1 allows only one incomplete frame at a time, so
//     most concurrent burst frames are dropped at the overflow check.
//   - The unreliable burst goes on channel 2; the reliable sentinel uses the
//     default channel 0.  The server's OnConnect only reads from channel 0
//     (conn.Recv), so burst traffic is auto-buffered by the router and drops
//     silently once the channel 2 event buffer fills.
func TestReassemblyBufferOverflowServerStable(t *testing.T) {
	// mtu=200: large enough for HandshakeInit (148 B), forces fragmentation on
	// 300-byte payloads (maxFrag=160 B → 2 fragments per event).
	const mtu = 200
	const burstN = 10        // unreliable fragmented events per goroutine
	const goroutines = 4     // concurrent burst senders
	const payloadSize = 300  // bytes; forces 2-fragment frames at mtu=200

	sentinelDone := make(chan struct{})

	addr, kp := serverSetup(t, wiresocket.ServerConfig{
		MaxPacketSize:       mtu,
		MaxIncompleteFrames: 1, // tight — most concurrent burst frames overflow
		OnConnect: func(conn *wiresocket.Conn) {
			for {
				e, err := conn.Recv(context.Background())
				if err != nil {
					return
				}
				if e.Type == 42 {
					close(sentinelDone)
					return
				}
			}
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	conn := mustDial(t, ctx, addr, kp, wiresocket.DialConfig{
		MaxPacketSize:       mtu,
		MaxIncompleteFrames: 64,
	})

	// ch2: unreliable, fragmented — exercises the reassembly overflow path.
	ch2 := conn.Channel(2)
	ch2.SetUnreliable()

	payload := make([]byte, payloadSize)
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < burstN; i++ {
				_ = ch2.Send(ctx, &wiresocket.Event{Type: 1, Payload: payload})
			}
		}()
	}
	wg.Wait()

	// Reliable sentinel (type 42) on the default channel 0.  The server receives
	// it via conn.Recv() and closes sentinelDone, proving it is alive after the
	// overflow.  Note: type 255 is reserved (channelCloseType) and must not be
	// used as an application event type.
	if err := conn.Send(ctx, &wiresocket.Event{Type: 42}); err != nil {
		t.Fatalf("reliable sentinel send: %v", err)
	}
	select {
	case <-sentinelDone:
		// server received the sentinel — overflow was handled without crash/deadlock
	case <-time.After(10 * time.Second):
		t.Fatal("reliable sentinel not received within 10 s — server may have crashed or deadlocked during reassembly overflow")
	}
}
