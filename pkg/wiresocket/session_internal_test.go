package wiresocket

import (
	"testing"
	"time"
)

// TestGCFragBufsEvictsStale verifies that gcFragBufs removes entries whose
// lastSeen is older than maxAge and returns their pool buffers without
// panicking.
func TestGCFragBufsEvictsStale(t *testing.T) {
	s := &session{
		fragBufs: make(map[uint32]*reassemblyBuf),
	}

	// Stale entry: first fragment received, second still missing; lastSeen 2s ago.
	bp := recvBufPool.Get().(*[]byte)
	stale := &reassemblyBuf{
		frags:    make([][]byte, 2),
		bufs:     []*[]byte{bp, nil},
		total:    2,
		received: 1,
		lastSeen: time.Now().Add(-2 * time.Second),
	}
	stale.frags[0] = []byte("fragment-data")
	s.fragBufs[1] = stale

	s.gcFragBufs(1 * time.Second)

	if _, ok := s.fragBufs[1]; ok {
		t.Error("stale entry (frameID=1) should have been evicted by GC")
	}
}

// TestGCFragBufsPreservesRecent verifies that a just-seen entry is not removed.
func TestGCFragBufsPreservesRecent(t *testing.T) {
	s := &session{
		fragBufs: make(map[uint32]*reassemblyBuf),
	}

	s.fragBufs[7] = &reassemblyBuf{
		frags:    make([][]byte, 2),
		bufs:     make([]*[]byte, 2),
		total:    2,
		received: 0,
		lastSeen: time.Now(), // just now — must survive GC
	}

	s.gcFragBufs(1 * time.Second)

	if _, ok := s.fragBufs[7]; !ok {
		t.Error("fresh entry (frameID=7) should not have been evicted by GC")
	}
}

// TestGCFragBufsAllEvicted verifies that when all entries are stale the map
// ends up empty.
func TestGCFragBufsAllEvicted(t *testing.T) {
	s := &session{
		fragBufs: make(map[uint32]*reassemblyBuf),
	}
	for id := uint32(0); id < 5; id++ {
		s.fragBufs[id] = &reassemblyBuf{
			frags:    make([][]byte, 1),
			bufs:     make([]*[]byte, 1),
			total:    1,
			received: 0,
			lastSeen: time.Now().Add(-10 * time.Second),
		}
	}

	s.gcFragBufs(1 * time.Second)

	if n := len(s.fragBufs); n != 0 {
		t.Errorf("expected empty map after all-stale GC, got %d entries", n)
	}
}

// TestGCFragBufsNilMap verifies that gcFragBufs does not panic when fragBufs
// has never been initialised (nil map).
func TestGCFragBufsNilMap(t *testing.T) {
	s := &session{} // fragBufs is nil
	s.gcFragBufs(1 * time.Second)
}

// TestGCFragBufsEmptyMap verifies that gcFragBufs is a no-op on an empty map.
func TestGCFragBufsEmptyMap(t *testing.T) {
	s := &session{fragBufs: make(map[uint32]*reassemblyBuf)}
	s.gcFragBufs(1 * time.Second)
	if len(s.fragBufs) != 0 {
		t.Errorf("expected empty map to stay empty, got %d entries", len(s.fragBufs))
	}
}
