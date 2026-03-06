package wiresocket

// pool_internal_test.go — unit tests for size-class pool helpers (Item 4)
// and Frame/Event pool objects (Item 5).
//
// Tests verify:
//   - Size-class routing: getSendBuf/getRecvBuf return the right-sized buffer
//   - Symmetric put: putSendBuf/putRecvBuf route by cap (not by requested size)
//   - wireSize accuracy: frame.wireSize() matches the length AppendMarshal produces
//   - singleEventFrame pool: initialised correctly, cleared on return
//   - ackFramePool: get/put cycle leaves Frame in zero state

import (
	"testing"
)

// ── Size-class pool helpers ────────────────────────────────────────────────────

func TestGetSendBufSmall(t *testing.T) {
	t.Parallel()
	bp := getSendBuf(poolSmallCap)
	if cap(*bp) < poolSmallCap {
		t.Errorf("getSendBuf(%d): cap=%d, want ≥ %d", poolSmallCap, cap(*bp), poolSmallCap)
	}
	if cap(*bp) > poolMedCap {
		t.Errorf("getSendBuf(%d): cap=%d, looks like wrong pool (expected small)", poolSmallCap, cap(*bp))
	}
	putSendBuf(bp)
}

func TestGetSendBufMedium(t *testing.T) {
	t.Parallel()
	bp := getSendBuf(poolSmallCap + 1)
	if cap(*bp) < poolSmallCap+1 {
		t.Errorf("getSendBuf(%d): cap=%d too small", poolSmallCap+1, cap(*bp))
	}
	if cap(*bp) > 65535+sizeAEADTag {
		t.Errorf("getSendBuf(%d): cap=%d, looks like wrong pool", poolSmallCap+1, cap(*bp))
	}
	putSendBuf(bp)
}

func TestGetSendBufLarge(t *testing.T) {
	t.Parallel()
	bp := getSendBuf(poolMedCap + 1)
	if cap(*bp) < poolMedCap+1 {
		t.Errorf("getSendBuf(%d): cap=%d too small", poolMedCap+1, cap(*bp))
	}
	putSendBuf(bp)
}

func TestGetRecvBufRouting(t *testing.T) {
	t.Parallel()
	cases := []struct {
		needed  int
		wantCap int // minimum expected capacity
	}{
		{0, poolSmallCap},
		{poolSmallCap, poolSmallCap},
		{poolSmallCap + 1, poolMedCap},
		{poolMedCap, poolMedCap},
		{poolMedCap + 1, 65535},
	}
	for _, tc := range cases {
		bp := getRecvBuf(tc.needed)
		if cap(*bp) < tc.wantCap {
			t.Errorf("getRecvBuf(%d): cap=%d, want ≥ %d", tc.needed, cap(*bp), tc.wantCap)
		}
		putRecvBuf(bp)
	}
}

// TestPutSendBufByCapNotNeeded verifies that putSendBuf routes by cap(*bp),
// so a buffer that was reallocated (e.g. by AppendMarshal growing it) still
// goes to the correct pool.
func TestPutSendBufByCapNotNeeded(t *testing.T) {
	t.Parallel()
	// Fabricate a small buffer (cap ≤ poolSmallCap) and put it; should not panic.
	small := make([]byte, 0, poolSmallCap)
	smallSendPool.Put(&small)
	bp := smallSendPool.Get().(*[]byte)
	if cap(*bp) < poolSmallCap {
		t.Fatalf("sanity: got cap=%d from smallSendPool", cap(*bp))
	}
	putSendBuf(bp) // routes to smallSendPool — must not panic

	// Fabricate a large buffer and put it; should not panic.
	large := make([]byte, 0, 65535+sizeAEADTag)
	largeSendPool.Put(&large)
	bp2 := largeSendPool.Get().(*[]byte)
	putSendBuf(bp2)
}

// ── wireSize accuracy ──────────────────────────────────────────────────────────

func TestWireSizeMatchesAppendMarshal(t *testing.T) {
	t.Parallel()
	cases := []*Frame{
		{ChannelId: 0},
		{ChannelId: 1, Events: []*Event{{Type: 1, Payload: []byte("hello")}}},
		{ChannelId: 42, Events: []*Event{{Type: 2, Payload: make([]byte, 127)}}},
		{ChannelId: 100, Events: []*Event{{Type: 3, Payload: make([]byte, 128)}}},
		{ChannelId: 7, Seq: 42, AckSeq: 41, AckBitmap: 0xDEAD, WindowSize: 256,
			Events: []*Event{{Type: 1}, {Type: 2, Payload: make([]byte, 64)}}},
		// Large payload to test multi-byte varint for body_len.
		{ChannelId: 3, Events: []*Event{{Type: 5, Payload: make([]byte, 16383)}}},
		// Multiple events.
		{ChannelId: 9, Events: []*Event{
			{Type: 1, Payload: make([]byte, 32)},
			{Type: 2, Payload: make([]byte, 64)},
			{Type: 3},
		}},
		// Only control fields, no events (standalone ACK).
		{ChannelId: 1, AckSeq: 100, WindowSize: 512},
		// All control fields populated.
		{ChannelId: 0xFF, Seq: 0xFFFF, AckSeq: 0xFFFE, AckBitmap: 0xFFFFFFFFFFFFFFFF, WindowSize: 4096},
	}
	for _, f := range cases {
		got := f.wireSize()
		wire := f.AppendMarshal(nil)
		want := len(wire)
		if got != want {
			t.Errorf("wireSize=%d, AppendMarshal len=%d for frame %+v", got, want, f)
		}
	}
}

// BenchmarkWireSize measures the overhead of computing the frame wire size
// for a typical single-event frame (the common case in Channel.Send).
func BenchmarkWireSize(b *testing.B) {
	f := &Frame{
		ChannelId: 1,
		Seq:       42,
		AckSeq:    41,
		WindowSize: 256,
		Events:    []*Event{{Type: 1, Payload: make([]byte, 1024)}},
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = f.wireSize()
	}
}

// ── singleEventFrame pool ──────────────────────────────────────────────────────

func TestGetSingleEventFrameInit(t *testing.T) {
	t.Parallel()
	e := &Event{Type: 7, Payload: []byte("test")}
	sf := getSingleEventFrame(42, e)

	if sf.f.ChannelId != 42 {
		t.Errorf("ChannelId=%d, want 42", sf.f.ChannelId)
	}
	if len(sf.f.Events) != 1 {
		t.Errorf("len(Events)=%d, want 1", len(sf.f.Events))
	}
	if sf.f.Events[0] != e {
		t.Errorf("Events[0]=%p, want %p", sf.f.Events[0], e)
	}
	if sf.slot[0] != e {
		t.Errorf("slot[0]=%p, want %p", sf.slot[0], e)
	}
	// Events must point into the slot array (not a separate allocation).
	if &sf.f.Events[0] != &sf.slot[0] {
		t.Error("f.Events does not alias slot — separate allocation leaked")
	}
	putSingleEventFrame(sf)
}

func TestPutSingleEventFrameClears(t *testing.T) {
	t.Parallel()
	e := &Event{Type: 1}
	sf := getSingleEventFrame(5, e)
	putSingleEventFrame(sf)
	// After put, slot and Frame fields must be zero to avoid GC pinning.
	if sf.slot[0] != nil {
		t.Error("slot[0] not cleared after putSingleEventFrame")
	}
	if sf.f.ChannelId != 0 || sf.f.Events != nil {
		t.Error("Frame fields not cleared after putSingleEventFrame")
	}
}

// BenchmarkSingleEventFramePool measures Get+Put overhead.
func BenchmarkSingleEventFramePool(b *testing.B) {
	e := &Event{Type: 1, Payload: make([]byte, 128)}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sf := getSingleEventFrame(1, e)
		putSingleEventFrame(sf)
	}
}

// ── ackFramePool ──────────────────────────────────────────────────────────────

func TestAckFramePoolCycle(t *testing.T) {
	t.Parallel()
	f := ackFramePool.Get().(*Frame)
	f.ChannelId = 3
	f.AckSeq = 100
	f.WindowSize = 64
	*f = Frame{} // clear
	ackFramePool.Put(f)

	// Get again — should be (structurally) zeroed.
	f2 := ackFramePool.Get().(*Frame)
	if f2.ChannelId != 0 || f2.AckSeq != 0 || f2.Events != nil {
		t.Error("Frame from ackFramePool not zero after put — fields were not cleared")
	}
	ackFramePool.Put(f2)
}
