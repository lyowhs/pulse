package wiresocket

import (
	"sync"
	"time"
)

// tokenBucket is a thread-safe token bucket rate limiter.
// It allows bursting up to burst bytes and then enforces a steady-state rate.
type tokenBucket struct {
	mu     sync.Mutex
	tokens float64 // current available tokens (bytes)
	rate   float64 // token refill rate in tokens per nanosecond
	burst  float64 // maximum token capacity
	last   int64   // unix nanoseconds of last refill
}

// newTokenBucket creates a token bucket for the given byte-per-second rate.
// The burst capacity equals the per-second rate (1-second burst window),
// allowing short bursts while keeping the CC-visible first-second throughput
// close to the configured rate.
func newTokenBucket(bps int64) *tokenBucket {
	rate := float64(bps) / 1e9 // convert bytes/sec → bytes/ns
	burst := float64(bps)      // 1-second burst capacity
	return &tokenBucket{
		tokens: burst,
		rate:   rate,
		burst:  burst,
		last:   time.Now().UnixNano(),
	}
}

// setRate updates the token bucket to a new rate.  It is safe to call
// concurrently with wait; the next call to wait will pick up the new rate.
func (b *tokenBucket) setRate(bps float64) {
	b.mu.Lock()
	b.rate = bps / 1e9 // bytes/ns
	newBurst := bps    // 1× burst (mirrors newTokenBucket)
	if b.tokens > newBurst {
		b.tokens = newBurst // clamp existing tokens if rate dropped
	}
	b.burst = newBurst
	b.mu.Unlock()
}

// wait blocks until n bytes of credit are available, then consumes them.
// It returns immediately on the happy path (tokens available).
// If the session closes (done is closed) before tokens are available, it
// returns ErrConnClosed.
func (b *tokenBucket) wait(done <-chan struct{}, n int) error {
	for {
		b.mu.Lock()
		now := time.Now().UnixNano()
		elapsed := float64(now - b.last)
		b.last = now
		b.tokens += elapsed * b.rate
		if b.tokens > b.burst {
			b.tokens = b.burst
		}
		fn := float64(n)
		if b.tokens >= fn {
			b.tokens -= fn
			b.mu.Unlock()
			return nil
		}
		// Calculate how long until we have enough tokens.
		needed := fn - b.tokens
		waitNs := int64(needed / b.rate)
		b.mu.Unlock()

		dbg("rate limit: throttling send", "need_bytes", n, "wait_ns", waitNs)

		// Wait for the calculated duration or until the session closes.
		timer := time.NewTimer(time.Duration(waitNs))
		select {
		case <-timer.C:
			// Tokens should be available; retry the consume loop.
		case <-done:
			timer.Stop()
			return ErrConnClosed
		}
	}
}
