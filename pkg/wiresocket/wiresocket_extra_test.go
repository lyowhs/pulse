package wiresocket_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	"example.com/pulse/pulse/pkg/wiresocket"
)

// TestGenerateKeypair verifies that GenerateKeypair produces non-zero keys,
// that public and private keys differ, and that successive calls return
// distinct key pairs.
func TestGenerateKeypair(t *testing.T) {
	kp, err := wiresocket.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	var zero [32]byte
	if kp.Public == zero {
		t.Error("Public key is all-zero")
	}
	if kp.Private == zero {
		t.Error("Private key is all-zero")
	}
	if kp.Public == kp.Private {
		t.Error("Public and Private keys are equal")
	}
	kp2, err := wiresocket.GenerateKeypair()
	if err != nil {
		t.Fatalf("second GenerateKeypair: %v", err)
	}
	if kp.Public == kp2.Public {
		t.Error("two successive GenerateKeypair calls returned the same public key")
	}
}

// TestFrameAppendMarshalAppends verifies that AppendMarshal appends wire bytes
// to an existing slice without overwriting its contents.
func TestFrameAppendMarshalAppends(t *testing.T) {
	prefix := []byte{0xAA, 0xBB, 0xCC}
	f := &wiresocket.Frame{
		ChannelId: 3,
		Events:    []*wiresocket.Event{{Type: 7, Payload: []byte("ping")}},
		Seq:       5,
	}
	dst := make([]byte, len(prefix), len(prefix)+64)
	copy(dst, prefix)
	got := f.AppendMarshal(dst)

	if len(got) <= len(prefix) {
		t.Fatalf("AppendMarshal did not append: len=%d, want > %d", len(got), len(prefix))
	}
	if !bytes.Equal(got[:len(prefix)], prefix) {
		t.Errorf("AppendMarshal clobbered prefix: got %x, want %x", got[:len(prefix)], prefix)
	}

	// The appended portion must round-trip cleanly.
	parsed, err := wiresocket.UnmarshalFrame(got[len(prefix):])
	if err != nil {
		t.Fatalf("UnmarshalFrame appended portion: %v", err)
	}
	if parsed.ChannelId != f.ChannelId {
		t.Errorf("ChannelId: got %d, want %d", parsed.ChannelId, f.ChannelId)
	}
	if len(parsed.Events) != 1 {
		t.Fatalf("events: got %d, want 1", len(parsed.Events))
	}
	if string(parsed.Events[0].Payload) != "ping" {
		t.Errorf("payload: got %q, want %q", parsed.Events[0].Payload, "ping")
	}
	if parsed.Seq != f.Seq {
		t.Errorf("Seq: got %d, want %d", parsed.Seq, f.Seq)
	}
}

// TestFrameEmptyFrameRoundtrip verifies that a frame carrying no events
// encodes and decodes without error.
func TestFrameEmptyFrameRoundtrip(t *testing.T) {
	f := &wiresocket.Frame{ChannelId: 5}
	b := f.Marshal()
	got, err := wiresocket.UnmarshalFrame(b)
	if err != nil {
		t.Fatalf("UnmarshalFrame: %v", err)
	}
	if got.ChannelId != 5 {
		t.Errorf("ChannelId: got %d, want 5", got.ChannelId)
	}
	if len(got.Events) != 0 {
		t.Errorf("Events: got %d, want 0", len(got.Events))
	}
}

// TestFrameZeroBytesUnmarshal verifies that UnmarshalFrame handles a nil/empty
// input without panicking or returning an error.
func TestFrameZeroBytesUnmarshal(t *testing.T) {
	f, err := wiresocket.UnmarshalFrame(nil)
	if err != nil {
		t.Fatalf("UnmarshalFrame(nil): %v", err)
	}
	if f == nil {
		t.Fatal("UnmarshalFrame(nil) returned nil Frame")
	}
	f2, err := wiresocket.UnmarshalFrame([]byte{})
	if err != nil {
		t.Fatalf("UnmarshalFrame([]byte{}): %v", err)
	}
	if f2 == nil {
		t.Fatal("UnmarshalFrame([]byte{}) returned nil Frame")
	}
}

// TestFrameStandaloneACKRoundtrip verifies that a frame carrying only
// reliability fields (no application events) encodes and decodes correctly.
// Standalone ACKs are used by the reliable protocol when no data is flowing.
func TestFrameStandaloneACKRoundtrip(t *testing.T) {
	f := &wiresocket.Frame{
		ChannelId:  12,
		AckSeq:     99,
		AckBitmap:  0b1010101010101010,
		WindowSize: 256,
	}
	b := f.Marshal()
	got, err := wiresocket.UnmarshalFrame(b)
	if err != nil {
		t.Fatalf("UnmarshalFrame: %v", err)
	}
	if got.ChannelId != f.ChannelId {
		t.Errorf("ChannelId: got %d, want %d", got.ChannelId, f.ChannelId)
	}
	if got.AckSeq != f.AckSeq {
		t.Errorf("AckSeq: got %d, want %d", got.AckSeq, f.AckSeq)
	}
	if got.AckBitmap != f.AckBitmap {
		t.Errorf("AckBitmap: got %b, want %b", got.AckBitmap, f.AckBitmap)
	}
	if got.WindowSize != f.WindowSize {
		t.Errorf("WindowSize: got %d, want %d", got.WindowSize, f.WindowSize)
	}
	if len(got.Events) != 0 {
		t.Errorf("Events: got %d, want 0", len(got.Events))
	}
}

// TestFrameHighChannelIDRoundtrip verifies that the full uint16 channel ID
// range (including values > 255) survives encode/decode.
func TestFrameHighChannelIDRoundtrip(t *testing.T) {
	for _, id := range []uint16{0, 255, 256, 1000, 65534} {
		f := &wiresocket.Frame{
			ChannelId: id,
			Events:    []*wiresocket.Event{{Type: 1}},
		}
		b := f.Marshal()
		got, err := wiresocket.UnmarshalFrame(b)
		if err != nil {
			t.Fatalf("id=%d: UnmarshalFrame: %v", id, err)
		}
		if got.ChannelId != id {
			t.Errorf("id=%d: got ChannelId %d", id, got.ChannelId)
		}
	}
}

// TestConnInflightCap verifies that InflightCap returns a positive value after
// a successful dial.
func TestConnInflightCap(t *testing.T) {
	addr, kp := serverSetup(t, wiresocket.ServerConfig{
		OnConnect: func(conn *wiresocket.Conn) { <-conn.Done() },
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn := mustDial(t, ctx, addr, kp)
	if cap := conn.InflightCap(); cap <= 0 {
		t.Errorf("InflightCap() = %d, want > 0", cap)
	}
}

// TestConnFlushReturnsFastUnreliable verifies that Flush on a conn whose only
// channel is unreliable returns promptly without waiting for ACKs.
func TestConnFlushReturnsFastUnreliable(t *testing.T) {
	addr, kp := serverSetup(t, wiresocket.ServerConfig{
		OnConnect: func(conn *wiresocket.Conn) {
			conn.Channel(0).SetUnreliable()
			<-conn.Done()
		},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn := mustDial(t, ctx, addr, kp)
	conn.Channel(0).SetUnreliable()

	// Fire a few unreliable sends; Flush must not block on ACKs.
	for i := 0; i < 5; i++ {
		_ = conn.Send(ctx, &wiresocket.Event{Type: uint8(i + 1)})
	}

	flushCtx, flushCancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer flushCancel()

	done := make(chan struct{})
	go func() {
		conn.Flush(flushCtx)
		close(done)
	}()

	select {
	case <-done:
		// expected — Flush completed without waiting for ACKs
	case <-flushCtx.Done():
		t.Error("Flush blocked > 200ms on a conn with only unreliable channels")
	}
}

// TestChannelUnreliableDelivery verifies that SetUnreliable still delivers
// events end-to-end on loopback and that Retransmits() returns 0.
func TestChannelUnreliableDelivery(t *testing.T) {
	const N = 20
	received := make(chan uint8, N)

	addr, kp := serverSetup(t, wiresocket.ServerConfig{
		OnConnect: func(conn *wiresocket.Conn) {
			ch := conn.Channel(1)
			ch.SetUnreliable()
			for {
				e, err := ch.Recv(context.Background())
				if err != nil {
					return
				}
				received <- e.Type
			}
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn := mustDial(t, ctx, addr, kp)
	ch := conn.Channel(1)
	ch.SetUnreliable()

	for i := 0; i < N; i++ {
		if err := ch.Send(ctx, &wiresocket.Event{Type: uint8(i + 1)}); err != nil {
			t.Fatalf("Send[%d]: %v", i, err)
		}
	}

	// On loopback all packets should arrive.
	got := 0
	deadline := time.Now().Add(3 * time.Second)
	for got < N && time.Now().Before(deadline) {
		select {
		case <-received:
			got++
		case <-time.After(50 * time.Millisecond):
		}
	}
	if got < N {
		t.Errorf("unreliable delivery: got %d/%d events on loopback", got, N)
	}
	if r := ch.Retransmits(); r != 0 {
		t.Errorf("Retransmits() = %d on unreliable channel, want 0", r)
	}
}

// TestChannelRetransmitsAfterSetUnreliable verifies that Retransmits() returns
// 0 after SetUnreliable is called (the reliable state is cleared).
func TestChannelRetransmitsAfterSetUnreliable(t *testing.T) {
	addr, kp := serverSetup(t, wiresocket.ServerConfig{
		OnConnect: func(conn *wiresocket.Conn) { <-conn.Done() },
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn := mustDial(t, ctx, addr, kp)

	ch := conn.Channel(2)
	ch.SetUnreliable()
	if r := ch.Retransmits(); r != 0 {
		t.Errorf("Retransmits() after SetUnreliable = %d, want 0", r)
	}
}

// TestPayloadExactBytesRoundtrip verifies that arbitrary binary payloads —
// including NUL bytes and all 256 byte values — are delivered byte-for-byte.
func TestPayloadExactBytesRoundtrip(t *testing.T) {
	payload := make([]byte, 256)
	for i := range payload {
		payload[i] = byte(i)
	}

	received := make(chan []byte, 1)
	addr, kp := serverSetup(t, wiresocket.ServerConfig{
		OnConnect: func(conn *wiresocket.Conn) {
			e, err := conn.Recv(context.Background())
			if err != nil {
				return
			}
			received <- e.Payload
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn := mustDial(t, ctx, addr, kp)
	if err := conn.Send(ctx, &wiresocket.Event{Type: 42, Payload: payload}); err != nil {
		t.Fatalf("Send: %v", err)
	}

	select {
	case got := <-received:
		if !bytes.Equal(got, payload) {
			first := -1
			for i := range payload {
				if i >= len(got) || got[i] != payload[i] {
					first = i
					break
				}
			}
			t.Errorf("payload mismatch: got %d bytes, want %d; first diff at index %d",
				len(got), len(payload), first)
		}
	case <-ctx.Done():
		t.Fatal("timeout: payload not received")
	}
}

// TestHighChannelIDWorks verifies that channel IDs near the uint16 maximum
// (65534 is the highest valid application ID) can be opened and used normally.
func TestHighChannelIDWorks(t *testing.T) {
	const highID = uint16(60000)
	received := make(chan uint8, 1)

	addr, kp := serverSetup(t, wiresocket.ServerConfig{
		OnConnect: func(conn *wiresocket.Conn) {
			ch := conn.Channel(highID)
			e, err := ch.Recv(context.Background())
			if err != nil {
				return
			}
			received <- e.Type
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn := mustDial(t, ctx, addr, kp)

	ch := conn.Channel(highID)
	if ch.ID() != highID {
		t.Fatalf("Channel.ID() = %d, want %d", ch.ID(), highID)
	}
	if err := ch.Send(ctx, &wiresocket.Event{Type: 77}); err != nil {
		t.Fatalf("Send on high channel ID: %v", err)
	}

	select {
	case got := <-received:
		if got != 77 {
			t.Errorf("received type %d, want 77", got)
		}
	case <-ctx.Done():
		t.Error("timeout: event on high channel ID not received")
	}
}

// TestMultipleEventTypesAndPayloads verifies that a frame carrying many events
// with distinct types and payloads is delivered without corruption.
func TestMultipleEventTypesAndPayloads(t *testing.T) {
	type wantEvent struct {
		typ     uint8
		payload string
	}
	events := []wantEvent{
		{1, "alpha"},
		{2, "beta"},
		{3, ""},   // empty payload
		{4, "delta\x00with\x00nulls"},
		{254, "max-type"},
	}

	received := make(chan wantEvent, len(events))
	addr, kp := serverSetup(t, wiresocket.ServerConfig{
		OnConnect: func(conn *wiresocket.Conn) {
			for range events {
				e, err := conn.Recv(context.Background())
				if err != nil {
					return
				}
				received <- wantEvent{e.Type, string(e.Payload)}
			}
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn := mustDial(t, ctx, addr, kp)

	for _, ev := range events {
		if err := conn.Send(ctx, &wiresocket.Event{Type: ev.typ, Payload: []byte(ev.payload)}); err != nil {
			t.Fatalf("Send type=%d: %v", ev.typ, err)
		}
	}
	conn.Flush(ctx)

	for i, want := range events {
		select {
		case got := <-received:
			if got.typ != want.typ || got.payload != want.payload {
				t.Errorf("event[%d]: got {type=%d payload=%q}, want {type=%d payload=%q}",
					i, got.typ, got.payload, want.typ, want.payload)
			}
		case <-ctx.Done():
			t.Fatalf("timeout: only received %d/%d events", i, len(events))
		}
	}
}

// TestTwoClientsEventIsolation verifies that two simultaneous clients receive
// only their own echoed events and not each other's.
func TestTwoClientsEventIsolation(t *testing.T) {
	addr, kp := serverSetup(t, wiresocket.ServerConfig{
		OnConnect: func(conn *wiresocket.Conn) {
			// Echo each event back with type += 100 to identify origin.
			for {
				e, err := conn.Recv(context.Background())
				if err != nil {
					return
				}
				_ = conn.Send(context.Background(), &wiresocket.Event{
					Type:    e.Type + 100,
					Payload: e.Payload,
				})
			}
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	connA := mustDial(t, ctx, addr, kp)
	connB := mustDial(t, ctx, addr, kp)

	const payloadA = "client-A"
	const payloadB = "client-B"
	if err := connA.Send(ctx, &wiresocket.Event{Type: 1, Payload: []byte(payloadA)}); err != nil {
		t.Fatalf("connA.Send: %v", err)
	}
	if err := connB.Send(ctx, &wiresocket.Event{Type: 2, Payload: []byte(payloadB)}); err != nil {
		t.Fatalf("connB.Send: %v", err)
	}

	eA, err := connA.Recv(ctx)
	if err != nil {
		t.Fatalf("connA.Recv: %v", err)
	}
	if eA.Type != 101 || string(eA.Payload) != payloadA {
		t.Errorf("connA got {type=%d payload=%q}, want {101 %q}", eA.Type, eA.Payload, payloadA)
	}

	eB, err := connB.Recv(ctx)
	if err != nil {
		t.Fatalf("connB.Recv: %v", err)
	}
	if eB.Type != 102 || string(eB.Payload) != payloadB {
		t.Errorf("connB got {type=%d payload=%q}, want {102 %q}", eB.Type, eB.Payload, payloadB)
	}
}
