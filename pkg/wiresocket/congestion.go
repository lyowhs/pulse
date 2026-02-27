package wiresocket

import (
	"sync"
	"time"
)

// CongestionConfig configures the built-in AIMD (Additive Increase /
// Multiplicative Decrease) congestion controller.
//
// The controller works by:
//   - Starting at InitialRate and doubling every ProbeInterval (slow start).
//   - Transitioning to additive increase (rate += IncreaseStep per interval)
//     once the slow-start threshold is learned or SlowStartThreshold is set.
//   - Halving the rate (multiplied by DecreaseMultiplier) when a loss event
//     is detected, and recording the new rate as the slow-start threshold.
//
// Loss detection requires reliable channels: the controller polls
// Channel.Retransmits() across all channels on the Conn.  Without reliable
// channels the controller stays in slow-start (rate only grows, never shrinks),
// which still provides a useful rate ramp rather than flooding the link at full
// speed from the start.
//
// CongestionControl overrides SendRateLimitBPS when both are set in DialConfig
// or ServerConfig.
type CongestionConfig struct {
	// InitialRate is the starting send rate in bytes/sec.
	// Default: 65536 (64 KiB/s) — conservative enough to survive 94% loss.
	InitialRate int64

	// MinRate is the floor send rate in bytes/sec.  The controller never drops
	// below this value even after repeated loss events.
	// Default: 8192 (8 KiB/s).
	MinRate int64

	// MaxRate is the ceiling send rate in bytes/sec.  0 means no ceiling.
	MaxRate int64

	// SlowStartThreshold is the rate at which slow start transitions to
	// additive increase.  0 means probe exponentially until first loss sets
	// the threshold automatically.
	SlowStartThreshold int64

	// ProbeInterval is how often the rate is adjusted.
	// Default: 300ms (1.5× the default reliable BaseRTO of 200ms, ensuring
	// loss is always visible at the next probe before the rate is doubled again).
	ProbeInterval time.Duration

	// IncreaseStep is the amount added to the rate per ProbeInterval during
	// the additive-increase phase.
	// Default: 4096 B/s (≈ one MTU per ProbeInterval, matching QUIC NewReno-style
	// congestion avoidance: additive increase of max_datagram_size per RTT).
	IncreaseStep int64

	// DecreaseMultiplier is the factor applied to the rate on a loss event.
	// Must be in (0, 1).  Default: 0.5 (standard TCP Reno halving).
	DecreaseMultiplier float64
}

// normalizedCC is an internal copy of CongestionConfig with defaults applied
// and all values pre-converted to float64.
type normalizedCC struct {
	initialRate        float64
	minRate            float64
	maxRate            float64
	slowStartThreshold float64
	probeInterval      time.Duration
	increaseStep       float64
	decreaseMultiplier float64
}

func normalizeCCConfig(c CongestionConfig) normalizedCC {
	n := normalizedCC{
		initialRate:        float64(c.InitialRate),
		minRate:            float64(c.MinRate),
		maxRate:            float64(c.MaxRate),
		slowStartThreshold: float64(c.SlowStartThreshold),
		probeInterval:      c.ProbeInterval,
		increaseStep:       float64(c.IncreaseStep),
		decreaseMultiplier: c.DecreaseMultiplier,
	}
	if n.initialRate <= 0 {
		n.initialRate = 64 * 1024 // 64 KiB/s
	}
	if n.minRate <= 0 {
		n.minRate = 8 * 1024 // 8 KiB/s
	}
	if n.probeInterval <= 0 {
		n.probeInterval = 300 * time.Millisecond
	}
	if n.increaseStep <= 0 {
		n.increaseStep = 4 * 1024 // 4096 B/s ≈ 1 MTU per ProbeInterval (QUIC NewReno-like)
	}
	if n.decreaseMultiplier <= 0 || n.decreaseMultiplier >= 1 {
		n.decreaseMultiplier = 0.5
	}
	return n
}

// aimdController implements sendLimiter with a dynamically adjusted rate.
// It wraps a tokenBucket whose rate is updated by a background probe goroutine.
//
// The controller is created once per Conn and re-used across session reconnects
// so that the learned rate (ssthresh) is preserved.
type aimdController struct {
	mu       sync.Mutex
	rate     float64 // current send rate, bytes/sec
	ssthresh float64 // slow-start threshold; 0 = still in slow-start
	lastRetx int64   // retransmit count snapshot from last probe
	cfg      normalizedCC

	tb             *tokenBucket    // rate-controlled gate; updated by probe
	getRetransmits func() int64    // closure over conn channels
	done           <-chan struct{}  // Conn lifetime signal
}

// newAIMDController creates a controller for the given Conn.  The goroutine is
// started separately via run().
func newAIMDController(cfg normalizedCC, conn *Conn) *aimdController {
	cc := &aimdController{
		rate:     cfg.initialRate,
		ssthresh: cfg.slowStartThreshold,
		cfg:      cfg,
		tb:       newTokenBucket(int64(cfg.initialRate)),
		getRetransmits: func() int64 {
			var total int64
			for i := range conn.channels {
				if ch := conn.channels[i].Load(); ch != nil {
					total += ch.Retransmits()
				}
			}
			return total
		},
		done: conn.done,
	}
	return cc
}

// wait implements sendLimiter; delegates to the inner token bucket.
func (cc *aimdController) wait(done <-chan struct{}, n int) error {
	return cc.tb.wait(done, n)
}

// currentRateKBps returns the current send rate in KiB/s for display purposes.
func (cc *aimdController) currentRateKBps() float64 {
	cc.mu.Lock()
	r := cc.rate
	cc.mu.Unlock()
	return r / 1024
}

// onReconnect re-baselines the retransmit counter after a session reconnect so
// that the reliable-state reset (which zeroes channel retransmit counters) is
// not misread as a loss event.
func (cc *aimdController) onReconnect() {
	cc.mu.Lock()
	cc.lastRetx = cc.getRetransmits()
	cc.mu.Unlock()
}

// probe is called every ProbeInterval to adjust the send rate.
func (cc *aimdController) probe() {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	retx := cc.getRetransmits()
	hasLoss := retx > cc.lastRetx
	cc.lastRetx = retx

	// Emit a probe-only warning when no reliable channels provide feedback.
	if retx == 0 && cc.ssthresh == 0 {
		dbg("congestion: no retransmit feedback — operating in probe-only mode (enable reliable channels for loss detection)")
	}

	var newRate float64
	switch {
	case hasLoss:
		// Multiplicative decrease: back off and record ssthresh.
		newRate = cc.rate * cc.cfg.decreaseMultiplier
		if newRate < cc.cfg.minRate {
			newRate = cc.cfg.minRate
		}
		cc.ssthresh = newRate

	case cc.ssthresh > 0 && cc.rate >= cc.ssthresh:
		// Additive increase phase.
		newRate = cc.rate + cc.cfg.increaseStep

	default:
		// Slow start: exponential growth.
		newRate = cc.rate * 2
		if cc.ssthresh > 0 && newRate > cc.ssthresh {
			newRate = cc.ssthresh
		}
	}

	if cc.cfg.maxRate > 0 && newRate > cc.cfg.maxRate {
		newRate = cc.cfg.maxRate
	}

	cc.rate = newRate
	cc.tb.setRate(newRate)

	dbg("congestion: rate update",
		"rate_kbps", int(newRate/1024),
		"ssthresh_kbps", int(cc.ssthresh/1024),
		"has_loss", hasLoss,
		"retx_total", retx,
	)
}

// run is the background goroutine.  It probes at ProbeInterval until the Conn
// closes.  Call go cc.run() after creating the controller.
func (cc *aimdController) run() {
	ticker := time.NewTicker(cc.cfg.probeInterval)
	defer ticker.Stop()
	for {
		select {
		case <-cc.done:
			return
		case <-ticker.C:
			cc.probe()
		}
	}
}
