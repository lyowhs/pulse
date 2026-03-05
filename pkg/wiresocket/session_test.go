package wiresocket_test

import (
	"context"
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
