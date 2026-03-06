package wiresocket

// coalescer_internal_test.go — unit tests for the coalescer bypass predicate
// (fillsPacket) introduced in Item 3 of the performance improvement series.
//
// The bypass eliminates 2 goroutine context switches per send when a single
// event fills an entire UDP frame — coalescing provides no batching benefit in
// that case.  Channel.Send calls c.fillsPacket(e) and, when true, falls through
// to the direct send path instead of pushing into the coalescer's input channel.

import (
	"testing"
)

// TestFillsPacketSmallEvent verifies that a small event (well below the frame
// limit) returns false — it should be coalesced with other events.
func TestFillsPacketSmallEvent(t *testing.T) {
	t.Parallel()
	c := &coalescer{maxFrameBytes: 1472}
	e := &Event{Payload: make([]byte, 64)} // evtWire = 67; 67+32=99 < 1472
	if c.fillsPacket(e) {
		t.Error("fillsPacket(64B payload, maxFrameBytes=1472) = true, want false")
	}
}

// TestFillsPacketLargeEvent verifies that an event whose wire size equals or
// exceeds maxFrameBytes returns true — the coalescer would flush immediately,
// so bypassing it avoids the goroutine overhead.
func TestFillsPacketLargeEvent(t *testing.T) {
	t.Parallel()
	// maxFrameBytes=1472; frameHeaderBudget=32.
	// payloadLen >= 127 → body_len = payloadLen+1 >= 128 → 2-byte varint → evtWire = payloadLen+4.
	// Threshold: payloadLen+4+32 >= 1472 → payloadLen >= 1436.
	c := &coalescer{maxFrameBytes: 1472}

	// Exactly at threshold: payloadLen=1436, body_len=1437 → evtWire=1440, 1440+32=1472 → true.
	eAt := &Event{Payload: make([]byte, 1436)}
	if !c.fillsPacket(eAt) {
		t.Error("fillsPacket(1436B payload, maxFrameBytes=1472) = false, want true (at threshold)")
	}

	// One byte below threshold: payloadLen=1435, body_len=1436 → evtWire=1439, 1439+32=1471 < 1472 → false.
	eBelow := &Event{Payload: make([]byte, 1435)}
	if c.fillsPacket(eBelow) {
		t.Error("fillsPacket(1435B payload, maxFrameBytes=1472) = true, want false (one below threshold)")
	}
}

// TestFillsPacketZeroMaxFrameBytes verifies that fillsPacket always returns
// false when maxFrameBytes==0 (unbounded — flush on timer only).
func TestFillsPacketZeroMaxFrameBytes(t *testing.T) {
	t.Parallel()
	c := &coalescer{maxFrameBytes: 0}

	small := &Event{Payload: make([]byte, 64)}
	if c.fillsPacket(small) {
		t.Error("fillsPacket(64B, maxFrameBytes=0) = true, want false")
	}

	large := &Event{Payload: make([]byte, 65000)}
	if c.fillsPacket(large) {
		t.Error("fillsPacket(65000B, maxFrameBytes=0) = true, want false")
	}
}

// TestFillsPacketVarintBoundary verifies the 2-byte varint boundary at
// body_len=128 (payloadLen=127) is handled correctly.  body_len = 1+payloadLen;
// at payloadLen=127 body_len=128 → varint takes 2 bytes → evtWire=payloadLen+4.
func TestFillsPacketVarintBoundary(t *testing.T) {
	t.Parallel()
	// maxFrameBytes=200; frameHeaderBudget=32.
	// payloadLen=127: body_len=128 → evtWire=131, 131+32=163 < 200 → false.
	// payloadLen=168: body_len=169 → evtWire=172, 172+32=204 >= 200 → true.
	// payloadLen=165: body_len=166 → evtWire=169, 169+32=201 >= 200 → true.
	// payloadLen=164: body_len=165 → evtWire=168, 168+32=200 >= 200 → true.
	// payloadLen=163: body_len=164 → evtWire=167, 167+32=199 < 200 → false.
	c := &coalescer{maxFrameBytes: 200}

	cases := []struct {
		payloadLen int
		want       bool
	}{
		{127, false}, // evtWire=131: 131+32=163 < 200
		{163, false}, // evtWire=167: 167+32=199 < 200
		{164, true},  // evtWire=168: 168+32=200 >= 200
		{168, true},  // evtWire=172: 172+32=204 >= 200
	}
	for _, tc := range cases {
		e := &Event{Payload: make([]byte, tc.payloadLen)}
		got := c.fillsPacket(e)
		if got != tc.want {
			t.Errorf("fillsPacket(payloadLen=%d, maxFrameBytes=200) = %v, want %v",
				tc.payloadLen, got, tc.want)
		}
	}
}

// BenchmarkFillsPacket measures the overhead of the fillsPacket predicate so
// we can verify it stays at zero allocations.
func BenchmarkFillsPacket(b *testing.B) {
	c := &coalescer{maxFrameBytes: 1472}
	e := &Event{Payload: make([]byte, 512)}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = c.fillsPacket(e)
	}
}
