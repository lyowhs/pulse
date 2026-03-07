package wiresocket

// ring_internal_test.go — unit tests and benchmarks for the lock-free MPSC
// event ring buffer (Item 2 optimisation).

import (
	"sync"
	"testing"
)

// ── Correctness ───────────────────────────────────────────────────────────────

func TestEventRingPushPop(t *testing.T) {
	t.Parallel()
	r := newEventRing(4)
	e := &Event{Type: 1, Payload: []byte("hello")}
	if !r.push(e) {
		t.Fatal("push on empty ring returned false")
	}
	got, ok := r.pop()
	if !ok {
		t.Fatal("pop on non-empty ring returned false")
	}
	if got != e {
		t.Errorf("pop returned wrong event: got %p, want %p", got, e)
	}
}

func TestEventRingFull(t *testing.T) {
	t.Parallel()
	r := newEventRing(4)
	e := &Event{Type: 1}
	for i := 0; i < 4; i++ {
		if !r.push(e) {
			t.Fatalf("push %d/4 returned false", i+1)
		}
	}
	// Ring is full; next push must drop.
	if r.push(e) {
		t.Error("push on full ring returned true (expected false / drop-newest)")
	}
}

func TestEventRingEmpty(t *testing.T) {
	t.Parallel()
	r := newEventRing(4)
	_, ok := r.pop()
	if ok {
		t.Error("pop on empty ring returned true")
	}
}

func TestEventRingFIFO(t *testing.T) {
	t.Parallel()
	r := newEventRing(8)
	events := []*Event{{Type: 1}, {Type: 2}, {Type: 3}}
	for _, e := range events {
		r.push(e)
	}
	for i, want := range events {
		got, ok := r.pop()
		if !ok {
			t.Fatalf("pop %d returned false", i)
		}
		if got != want {
			t.Errorf("FIFO order broken at %d: got type %d, want %d", i, got.Type, want.Type)
		}
	}
}

func TestEventRingLen(t *testing.T) {
	t.Parallel()
	r := newEventRing(8)
	if r.Len() != 0 {
		t.Errorf("Len of empty ring: got %d, want 0", r.Len())
	}
	e := &Event{Type: 1}
	r.push(e)
	r.push(e)
	if r.Len() != 2 {
		t.Errorf("Len after 2 pushes: got %d, want 2", r.Len())
	}
	r.pop()
	if r.Len() != 1 {
		t.Errorf("Len after 1 pop: got %d, want 1", r.Len())
	}
}

func TestEventRingCap(t *testing.T) {
	t.Parallel()
	r := newEventRing(5) // rounded up to 8
	if r.Cap() != 8 {
		t.Errorf("Cap: got %d, want 8 (rounded up from 5)", r.Cap())
	}
}

func TestEventRingCloseSig(t *testing.T) {
	t.Parallel()
	r := newEventRing(4)
	done := make(chan struct{})
	go func() {
		defer close(done)
		select {
		case <-r.Sig():
		case <-r.Done():
		}
	}()
	r.close()
	<-done
}

// TestEventRingConcurrentPush verifies that multiple concurrent producers do
// not lose events (MPSC property: all pushes that return true are eventually
// popped, in some order).
func TestEventRingConcurrentPush(t *testing.T) {
	t.Parallel()
	const producers = 8
	const perProducer = 64
	r := newEventRing(producers * perProducer)

	var wg sync.WaitGroup
	for p := 0; p < producers; p++ {
		p := p
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perProducer; i++ {
				e := &Event{Type: uint8(p), Payload: []byte{byte(i)}}
				// Ring is large enough that no push should fail.
				if !r.push(e) {
					t.Errorf("producer %d: push %d lost (ring full)", p, i)
				}
			}
		}()
	}
	wg.Wait()

	got := 0
	for {
		_, ok := r.pop()
		if !ok {
			break
		}
		got++
	}
	if got != producers*perProducer {
		t.Errorf("concurrent push: got %d events, want %d", got, producers*perProducer)
	}
}

// ── Benchmarks ────────────────────────────────────────────────────────────────

// BenchmarkEventRingPush measures the cost of a single push on an
// uncontended ring (single producer, no concurrent consumers).
func BenchmarkEventRingPushUncontended(b *testing.B) {
	r := newEventRing(b.N + 1)
	e := &Event{Type: 1}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		r.push(e)
	}
}

// BenchmarkEventRingPop measures the cost of a single pop when the ring is
// pre-filled (no wait / spin).
func BenchmarkEventRingPopNoWait(b *testing.B) {
	r := newEventRing(b.N + 1)
	e := &Event{Type: 1}
	for i := 0; i < b.N; i++ {
		r.push(e)
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		r.pop()
	}
}

// BenchmarkEventRingPushPop measures the round-trip cost of one push + one pop
// in a tight loop (simulates a single-producer, single-consumer hot path).
func BenchmarkEventRingPushPop(b *testing.B) {
	r := newEventRing(64)
	e := &Event{Type: 1}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		r.push(e)
		r.pop()
	}
}

// BenchmarkEventRingPushConcurrent measures push throughput with N concurrent
// producers all pushing to the same ring (pure producer contention).
// A single background goroutine drains the ring so it never fills.
// pop() is SPSC (single-consumer only) so it must not be called from the
// parallel producer goroutines.
func BenchmarkEventRingPushConcurrent(b *testing.B) {
	const ringCap = 1 << 16 // 64K slots
	r := newEventRing(ringCap)
	e := &Event{Type: 1}

	// Background drainer: single consumer pops items as fast as they arrive.
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
				r.pop()
			}
		}
	}()
	defer close(stop)

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			r.push(e)
		}
	})
}
