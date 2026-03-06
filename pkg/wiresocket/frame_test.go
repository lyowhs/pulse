package wiresocket_test

import (
	"testing"

	"example.com/pulse/pulse/pkg/wiresocket"
)

// TestFrameRoundtrip verifies Frame/Event encode-decode correctness.
func TestFrameRoundtrip(t *testing.T) {
	original := &wiresocket.Frame{
		ChannelId: 17,
		Events: []*wiresocket.Event{
			{Type: 1, Payload: []byte{0xde, 0xad, 0xbe, 0xef}},
			{Type: 2},
			{Type: 3, Payload: []byte("binary\x00data")},
		},
	}
	b := original.Marshal()
	got, err := wiresocket.UnmarshalFrame(b)
	if err != nil {
		t.Fatal(err)
	}
	if got.ChannelId != original.ChannelId {
		t.Errorf("ChannelId: got %d, want %d", got.ChannelId, original.ChannelId)
	}
	if len(got.Events) != len(original.Events) {
		t.Fatalf("got %d events, want %d", len(got.Events), len(original.Events))
	}
	for i, e := range got.Events {
		orig := original.Events[i]
		if e.Type != orig.Type {
			t.Errorf("[%d] type: got %d, want %d", i, e.Type, orig.Type)
		}
		if string(e.Payload) != string(orig.Payload) {
			t.Errorf("[%d] payload: got %q, want %q", i, e.Payload, orig.Payload)
		}
	}
}

// TestFrameReliabilityFields verifies that the reliability fields (Seq, AckSeq,
// AckBitmap, WindowSize) survive a full encode/decode round-trip.
func TestFrameReliabilityFields(t *testing.T) {
	cases := []*wiresocket.Frame{
		// Data frame with Seq only.
		{
			ChannelId: 7,
			Seq:       42,
			Events:    []*wiresocket.Event{{Type: 1, Payload: []byte("hi")}},
		},
		// ACK-only frame.
		{
			ChannelId:  0,
			AckSeq:     100,
			AckBitmap:  0xDEADBEEFCAFEBABE,
			WindowSize: 256,
		},
		// Full bidirectional frame.
		{
			ChannelId:  3,
			Seq:        1,
			AckSeq:     5,
			AckBitmap:  0b10101010,
			WindowSize: 128,
			Events: []*wiresocket.Event{
				{Type: 9},
				{Type: 10, Payload: []byte("payload")},
			},
		},
		// All optional fields zero — must round-trip as zero.
		{ChannelId: 255, Events: []*wiresocket.Event{{Type: 1}}},
	}

	for i, f := range cases {
		b := f.Marshal()
		got, err := wiresocket.UnmarshalFrame(b)
		if err != nil {
			t.Fatalf("case %d: UnmarshalFrame: %v", i, err)
		}
		if got.ChannelId != f.ChannelId {
			t.Errorf("case %d: ChannelId: got %d, want %d", i, got.ChannelId, f.ChannelId)
		}
		if got.Seq != f.Seq {
			t.Errorf("case %d: Seq: got %d, want %d", i, got.Seq, f.Seq)
		}
		if got.AckSeq != f.AckSeq {
			t.Errorf("case %d: AckSeq: got %d, want %d", i, got.AckSeq, f.AckSeq)
		}
		if got.AckBitmap != f.AckBitmap {
			t.Errorf("case %d: AckBitmap: got %016x, want %016x", i, got.AckBitmap, f.AckBitmap)
		}
		if got.WindowSize != f.WindowSize {
			t.Errorf("case %d: WindowSize: got %d, want %d", i, got.WindowSize, f.WindowSize)
		}
		if len(got.Events) != len(f.Events) {
			t.Fatalf("case %d: len(Events): got %d, want %d", i, len(got.Events), len(f.Events))
		}
		for j, e := range got.Events {
			orig := f.Events[j]
			if e.Type != orig.Type || string(e.Payload) != string(orig.Payload) {
				t.Errorf("case %d event %d: got {%d %q}, want {%d %q}",
					i, j, e.Type, e.Payload, orig.Type, orig.Payload)
			}
		}
	}
}

// TestFrameEmptyDecode verifies that an empty byte slice decodes without error.
func TestFrameEmptyDecode(t *testing.T) {
	got, err := wiresocket.UnmarshalFrame([]byte{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Events) != 0 {
		t.Errorf("expected 0 events, got %d", len(got.Events))
	}
}

// TestFrameLargePayload verifies that events with payloads ≥ 128 bytes round-trip
// correctly.  Payloads of this size cause the protobuf LEN-field length varint
// to use two bytes (body = 1+128 = 129 ≥ 128), exercising the multi-byte
// varint path in both AppendMarshal and UnmarshalFrame.
func TestFrameLargePayload(t *testing.T) {
	for _, size := range []int{127, 128, 129, 255, 256, 1000} {
		payload := make([]byte, size)
		for i := range payload {
			payload[i] = byte(i & 0xFF)
		}
		f := &wiresocket.Frame{
			ChannelId: 3,
			Events:    []*wiresocket.Event{{Type: 42, Payload: payload}},
		}
		wire := f.Marshal()
		got, err := wiresocket.UnmarshalFrame(wire)
		if err != nil {
			t.Fatalf("size=%d: UnmarshalFrame: %v", size, err)
		}
		if len(got.Events) != 1 {
			t.Fatalf("size=%d: got %d events, want 1", size, len(got.Events))
		}
		e := got.Events[0]
		if e.Type != 42 {
			t.Errorf("size=%d: Type=%d, want 42", size, e.Type)
		}
		if len(e.Payload) != size {
			t.Errorf("size=%d: payload len=%d, want %d", size, len(e.Payload), size)
		}
		for i, b := range e.Payload {
			if b != byte(i&0xFF) {
				t.Errorf("size=%d: payload[%d]=%d, want %d", size, i, b, byte(i&0xFF))
				break
			}
		}
	}
}

// TestFrameAppendMarshal verifies that AppendMarshal appends the encoding to a
// non-empty dst without overwriting or modifying the existing bytes.
func TestFrameAppendMarshal(t *testing.T) {
	prefix := []byte{0xAA, 0xBB, 0xCC}
	f := &wiresocket.Frame{
		ChannelId: 1,
		Events:    []*wiresocket.Event{{Type: 7, Payload: []byte("hello")}},
	}
	dst := append([]byte(nil), prefix...)
	result := f.AppendMarshal(dst)

	// The first three bytes must be unchanged.
	for i, b := range prefix {
		if result[i] != b {
			t.Errorf("prefix[%d] modified: got %02x, want %02x", i, result[i], b)
		}
	}

	// The remainder must decode to the original frame.
	wire := result[len(prefix):]
	got, err := wiresocket.UnmarshalFrame(wire)
	if err != nil {
		t.Fatalf("UnmarshalFrame of AppendMarshal suffix: %v", err)
	}
	if got.ChannelId != f.ChannelId {
		t.Errorf("ChannelId: got %d, want %d", got.ChannelId, f.ChannelId)
	}
	if len(got.Events) != 1 || got.Events[0].Type != 7 || string(got.Events[0].Payload) != "hello" {
		t.Errorf("decoded event mismatch: %+v", got.Events)
	}
}

// TestFrameTruncatedBody verifies that a 1-byte buffer (not enough for the
// 2-byte channel ID) returns a decode error.
func TestFrameTruncatedBody(t *testing.T) {
	_, err := wiresocket.UnmarshalFrame([]byte{0x01})
	if err == nil {
		t.Error("UnmarshalFrame with 1-byte buffer: expected error, got nil")
	}
}

// TestUnmarshalFrameBodyErrorPaths exercises every error branch in the body
// parser (consumeField / consumeVarint) by feeding crafted malformed wire
// bytes to UnmarshalFrame.  Each case must return a non-nil error.
func TestUnmarshalFrameBodyErrorPaths(t *testing.T) {
	cases := []struct {
		name string
		wire []byte
	}{
		{
			// Tag varint ends immediately — no terminating byte.
			name: "truncated_varint_tag",
			wire: []byte{0x00, 0x00, 0x80},
		},
		{
			// Tag varint spans 11 bytes with continuation bits set — overflow.
			name: "varint_overflow_tag",
			wire: append([]byte{0x00, 0x00},
				0x80, 0x80, 0x80, 0x80, 0x80,
				0x80, 0x80, 0x80, 0x80, 0x80, 0x80),
		},
		{
			// Field 4 wire type 1 (I64 — AckBitmap) with only 2 payload bytes
			// instead of the required 8.
			// Tag: (4<<3)|1 = 0x21
			name: "truncated_i64",
			wire: []byte{0x00, 0x00, 0x21, 0x01, 0x02},
		},
		{
			// Field 1 wire type 2 (LEN — event body) with length=16 but zero
			// data bytes following.
			// Tag: (1<<3)|2 = 0x0A; length varint: 0x10 = 16
			name: "truncated_len_value",
			wire: []byte{0x00, 0x00, 0x0A, 0x10},
		},
		{
			// Tag byte 0x03 encodes field=0, wire type=3 — not a valid wire type.
			name: "unknown_wire_type",
			wire: []byte{0x00, 0x00, 0x03},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			_, err := wiresocket.UnmarshalFrame(tc.wire)
			if err == nil {
				t.Errorf("UnmarshalFrame(%s): expected error, got nil", tc.name)
			}
		})
	}
}
