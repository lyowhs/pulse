package wiresocket

import (
	"sync"
	"testing"
	"time"
)

// TestTokenBucketSetRateClampsTokens verifies that lowering the rate clamps any
// accumulated token surplus to the new (smaller) burst capacity.
func TestTokenBucketSetRateClampsTokens(t *testing.T) {
	// Start at 1 MB/s: burst = 1 MB, tokens start full.
	const initialBPS int64 = 1 << 20
	b := newTokenBucket(initialBPS)

	// Drop to 100 B/s (burst = 100 B). Existing ~1 MB of tokens must be clamped.
	const lowBPS = 100.0
	b.setRate(lowBPS)

	b.mu.Lock()
	gotTokens := b.tokens
	gotBurst := b.burst
	gotRate := b.rate
	b.mu.Unlock()

	if gotBurst != lowBPS {
		t.Errorf("burst: got %v, want %v", gotBurst, lowBPS)
	}
	if gotTokens > gotBurst {
		t.Errorf("tokens %v > burst %v: setRate did not clamp on rate decrease", gotTokens, gotBurst)
	}
	wantRate := lowBPS / 1e9
	if gotRate != wantRate {
		t.Errorf("rate: got %v, want %v", gotRate, wantRate)
	}
}

// TestTokenBucketSetRateNoClampOnIncrease verifies that raising the rate does
// not reduce tokens that are already below the new burst ceiling.
func TestTokenBucketSetRateNoClampOnIncrease(t *testing.T) {
	const initialBPS int64 = 1000
	b := newTokenBucket(initialBPS)

	// Manually set tokens to a mid-range value below the current burst.
	const setTokens = 500.0
	b.mu.Lock()
	b.tokens = setTokens
	b.mu.Unlock()

	// Double the rate; burst grows to 2000, tokens (500) should be untouched.
	const newBPS = 2000.0
	b.setRate(newBPS)

	b.mu.Lock()
	gotTokens := b.tokens
	gotBurst := b.burst
	b.mu.Unlock()

	if gotBurst != newBPS {
		t.Errorf("burst: got %v, want %v", gotBurst, newBPS)
	}
	if gotTokens != setTokens {
		t.Errorf("tokens: got %v, want %v (should not be clamped on rate increase)", gotTokens, setTokens)
	}
}

// TestTokenBucketWaitTokensAvailableReturnsNil covers the fast path where
// sufficient tokens are already present — wait() must return nil immediately.
func TestTokenBucketWaitTokensAvailableReturnsNil(t *testing.T) {
	const bps int64 = 1 << 20 // 1 MB/s; starts with full burst
	b := newTokenBucket(bps)

	done := make(chan struct{})
	defer close(done)

	if err := b.wait(done, 100); err != nil {
		t.Errorf("wait with tokens available: got %v, want nil", err)
	}
}

// TestTokenBucketWaitDoneClosedReturnsErrConnClosed verifies that wait()
// returns ErrConnClosed when the done channel is closed before enough tokens
// accumulate.
func TestTokenBucketWaitDoneClosedReturnsErrConnClosed(t *testing.T) {
	// Zero tokens, rate so slow the request can never be satisfied before done closes.
	b := &tokenBucket{
		mu:     sync.Mutex{},
		tokens: 0,
		rate:   1.0 / 1e9, // 1 B/s in B/ns
		burst:  1,
		last:   time.Now().UnixNano(),
	}

	done := make(chan struct{})
	go func() {
		time.Sleep(20 * time.Millisecond)
		close(done)
	}()

	err := b.wait(done, 1_000_000) // 1 MB — impossible at 1 B/s
	if err != ErrConnClosed {
		t.Errorf("wait with closed done: got %v, want ErrConnClosed", err)
	}
}
