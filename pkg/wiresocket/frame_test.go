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
