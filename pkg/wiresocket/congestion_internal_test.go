package wiresocket

import (
	"sync"
	"testing"
	"time"
)

// TestNormalizeCCConfigDefaults verifies that zero-value fields get the
// documented defaults applied.
func TestNormalizeCCConfigDefaults(t *testing.T) {
	n := normalizeCCConfig(CongestionConfig{})
	if n.initialRate != 64*1024 {
		t.Errorf("initialRate default: got %.0f, want 65536", n.initialRate)
	}
	if n.minRate != 8*1024 {
		t.Errorf("minRate default: got %.0f, want 8192", n.minRate)
	}
	if n.probeInterval != 300*time.Millisecond {
		t.Errorf("probeInterval default: got %v, want 300ms", n.probeInterval)
	}
	if n.increaseStep != 4*1024 {
		t.Errorf("increaseStep default: got %.0f, want 4096", n.increaseStep)
	}
	if n.decreaseMultiplier != 0.5 {
		t.Errorf("decreaseMultiplier default: got %.2f, want 0.5", n.decreaseMultiplier)
	}
}

// TestNormalizeCCConfigCustom verifies that explicit values are preserved.
func TestNormalizeCCConfigCustom(t *testing.T) {
	cfg := CongestionConfig{
		InitialRate:        100_000,
		MinRate:            10_000,
		MaxRate:            1_000_000,
		SlowStartThreshold: 500_000,
		ProbeInterval:      500 * time.Millisecond,
		IncreaseStep:       8192,
		DecreaseMultiplier: 0.7,
	}
	n := normalizeCCConfig(cfg)
	if n.initialRate != 100_000 {
		t.Errorf("initialRate: got %.0f, want 100000", n.initialRate)
	}
	if n.maxRate != 1_000_000 {
		t.Errorf("maxRate: got %.0f, want 1000000", n.maxRate)
	}
	if n.slowStartThreshold != 500_000 {
		t.Errorf("slowStartThreshold: got %.0f, want 500000", n.slowStartThreshold)
	}
	if n.probeInterval != 500*time.Millisecond {
		t.Errorf("probeInterval: got %v, want 500ms", n.probeInterval)
	}
	if n.increaseStep != 8192 {
		t.Errorf("increaseStep: got %.0f, want 8192", n.increaseStep)
	}
	if n.decreaseMultiplier != 0.7 {
		t.Errorf("decreaseMultiplier: got %.2f, want 0.7", n.decreaseMultiplier)
	}
}

// TestNormalizeCCConfigDecreaseMultiplierOutOfRange verifies that out-of-range
// (≤0 or ≥1) decreaseMultiplier falls back to the default 0.5.
func TestNormalizeCCConfigDecreaseMultiplierOutOfRange(t *testing.T) {
	for _, bad := range []float64{0, -0.5, 1.0, 1.5} {
		n := normalizeCCConfig(CongestionConfig{DecreaseMultiplier: bad})
		if n.decreaseMultiplier != 0.5 {
			t.Errorf("decreaseMultiplier(%v): got %.2f, want 0.5", bad, n.decreaseMultiplier)
		}
	}
}

// TestAIMDControllerSlowStart verifies that probe() in slow-start doubles the
// rate each call until ssthresh is reached.
func TestAIMDControllerSlowStart(t *testing.T) {
	done := make(chan struct{})
	defer close(done)

	cfg := normalizeCCConfig(CongestionConfig{
		InitialRate:   1000,
		MaxRate:       0,
		ProbeInterval: time.Minute, // prevent auto-probing
	})

	// Build a minimal fake Conn for newAIMDController.
	conn := &Conn{done: done}

	cc := newAIMDController(cfg, conn)

	// Manually probe with no loss: rate should double each time (slow start).
	cc.probe()
	cc.mu.Lock()
	if cc.rate != 2000 {
		t.Errorf("after probe 1: rate=%.0f, want 2000", cc.rate)
	}
	cc.mu.Unlock()

	cc.probe()
	cc.mu.Lock()
	if cc.rate != 4000 {
		t.Errorf("after probe 2: rate=%.0f, want 4000", cc.rate)
	}
	cc.mu.Unlock()
}

// TestAIMDControllerLossEvent verifies that probe() halves the rate when a
// loss event is detected (retransmit count increases).
func TestAIMDControllerLossEvent(t *testing.T) {
	done := make(chan struct{})
	defer close(done)

	cfg := normalizeCCConfig(CongestionConfig{
		InitialRate:   10_000,
		ProbeInterval: time.Minute,
	})

	conn := &Conn{done: done}
	cc := newAIMDController(cfg, conn)

	// Simulate a loss: inject a non-zero retransmit count by replacing the
	// getRetransmits closure with a custom one.
	var retxCount int64
	var mu sync.Mutex
	cc.getRetransmits = func() int64 {
		mu.Lock()
		defer mu.Unlock()
		return retxCount
	}

	// First probe: no loss, slow start doubles to 20000.
	cc.probe()
	cc.mu.Lock()
	if cc.rate != 20_000 {
		t.Errorf("after probe 1: rate=%.0f, want 20000", cc.rate)
	}
	cc.mu.Unlock()

	// Simulate a loss event by incrementing retx.
	mu.Lock()
	retxCount = 1
	mu.Unlock()

	// Second probe: loss detected → halve.
	cc.probe()
	cc.mu.Lock()
	if cc.rate != 10_000 {
		t.Errorf("after loss probe: rate=%.0f, want 10000", cc.rate)
	}
	// ssthresh should be set to new rate.
	if cc.ssthresh != 10_000 {
		t.Errorf("ssthresh after loss: %.0f, want 10000", cc.ssthresh)
	}
	cc.mu.Unlock()
}

// TestAIMDControllerAdditiveIncrease verifies that once ssthresh is set and
// rate >= ssthresh, probe() adds increaseStep per call instead of doubling.
func TestAIMDControllerAdditiveIncrease(t *testing.T) {
	done := make(chan struct{})
	defer close(done)

	const step float64 = 4096
	cfg := normalizeCCConfig(CongestionConfig{
		InitialRate:        10_000,
		SlowStartThreshold: 10_000, // start directly in AI phase
		IncreaseStep:       int64(step),
		ProbeInterval:      time.Minute,
	})

	conn := &Conn{done: done}
	cc := newAIMDController(cfg, conn)
	// Override retransmits to always 0 (no loss).
	cc.getRetransmits = func() int64 { return 0 }

	// rate(10000) >= ssthresh(10000) → additive increase.
	cc.probe()
	cc.mu.Lock()
	wantRate := 10_000 + step
	if cc.rate != wantRate {
		t.Errorf("after AI probe: rate=%.0f, want %.0f", cc.rate, wantRate)
	}
	cc.mu.Unlock()
}

// TestAIMDControllerMaxRateCap verifies that probe() never exceeds MaxRate.
func TestAIMDControllerMaxRateCap(t *testing.T) {
	done := make(chan struct{})
	defer close(done)

	cfg := normalizeCCConfig(CongestionConfig{
		InitialRate: 5_000,
		MaxRate:     8_000,
		ProbeInterval: time.Minute,
	})

	conn := &Conn{done: done}
	cc := newAIMDController(cfg, conn)
	cc.getRetransmits = func() int64 { return 0 }

	// Slow start: 5000 → 8000 (capped at MaxRate).
	cc.probe()
	cc.mu.Lock()
	if cc.rate != 8_000 {
		t.Errorf("after capped probe: rate=%.0f, want 8000", cc.rate)
	}
	cc.mu.Unlock()
}

// TestAIMDControllerMinRateFloor verifies that the rate never drops below
// MinRate even after repeated loss events.
func TestAIMDControllerMinRateFloor(t *testing.T) {
	done := make(chan struct{})
	defer close(done)

	const minRate = 8192.0
	cfg := normalizeCCConfig(CongestionConfig{
		InitialRate:   minRate,
		MinRate:       int64(minRate),
		ProbeInterval: time.Minute,
	})

	conn := &Conn{done: done}
	cc := newAIMDController(cfg, conn)

	var retx int64 = 1
	cc.getRetransmits = func() int64 { return retx }
	// Simulate repeated loss.
	for i := 0; i < 10; i++ {
		retx++
		cc.probe()
		cc.mu.Lock()
		if cc.rate < minRate {
			t.Errorf("probe %d: rate=%.0f dropped below minRate=%.0f", i, cc.rate, minRate)
		}
		cc.mu.Unlock()
	}
}

// TestAIMDControllerCurrentRateKBps verifies that currentRateKBps returns the
// rate in KiB/s.
func TestAIMDControllerCurrentRateKBps(t *testing.T) {
	done := make(chan struct{})
	defer close(done)

	cfg := normalizeCCConfig(CongestionConfig{InitialRate: 1024 * 1024}) // 1 MiB/s
	conn := &Conn{done: done}
	cc := newAIMDController(cfg, conn)
	got := cc.currentRateKBps()
	if got != 1024 {
		t.Errorf("currentRateKBps: got %.1f, want 1024", got)
	}
}
