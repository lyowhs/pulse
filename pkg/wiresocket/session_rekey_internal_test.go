package wiresocket

import (
	"sync/atomic"
	"testing"
	"time"
)

// TestNeedsRekeyDisabledWhenZero verifies that a session with rekeyAfterTime==0
// (e.g. server-side sessions) never reports needing a rekey regardless of age.
func TestNeedsRekeyDisabledWhenZero(t *testing.T) {
	s := &session{
		rekeyAfterTime: 0,
		created:        time.Now().Add(-24 * time.Hour), // very old
	}
	if s.needsRekey() {
		t.Error("needsRekey() = true, want false when rekeyAfterTime == 0")
	}
}

// TestNeedsRekeyNotYetExpired verifies that a fresh session does not report
// needing a rekey.
func TestNeedsRekeyNotYetExpired(t *testing.T) {
	s := &session{
		rekeyAfterTime: 120 * time.Second,
		created:        time.Now(),
	}
	if s.needsRekey() {
		t.Error("needsRekey() = true for a brand-new session, want false")
	}
}

// TestNeedsRekeyTimeExpired verifies that a session older than rekeyAfterTime
// reports needing a rekey.
func TestNeedsRekeyTimeExpired(t *testing.T) {
	s := &session{
		rekeyAfterTime: 100 * time.Millisecond,
		created:        time.Now().Add(-200 * time.Millisecond),
	}
	if !s.needsRekey() {
		t.Error("needsRekey() = false, want true when session has exceeded rekeyAfterTime")
	}
}

// TestNeedsRekeyMessageCount verifies that reaching rekeyAfterMessages triggers
// the rekey flag even when the session is young.
func TestNeedsRekeyMessageCount(t *testing.T) {
	s := &session{
		rekeyAfterTime: 120 * time.Second,
		created:        time.Now(),
	}
	atomic.StoreUint64(&s.sendCounter, rekeyAfterMessages)
	if !s.needsRekey() {
		t.Error("needsRekey() = false, want true when sendCounter >= rekeyAfterMessages")
	}
}

// TestNeedsRekeyMessageCountBelowThreshold verifies that a counter just below
// the threshold does not trigger.
func TestNeedsRekeyMessageCountBelowThreshold(t *testing.T) {
	s := &session{
		rekeyAfterTime: 120 * time.Second,
		created:        time.Now(),
	}
	atomic.StoreUint64(&s.sendCounter, rekeyAfterMessages-1)
	if s.needsRekey() {
		t.Error("needsRekey() = true, want false when sendCounter < rekeyAfterMessages")
	}
}

// TestDialConfigDefaultsRekeyAfterTime verifies that a zero RekeyAfterTime in
// DialConfig is replaced with defaultRekeyAfterTime after calling defaults().
func TestDialConfigDefaultsRekeyAfterTime(t *testing.T) {
	cfg := DialConfig{}
	cfg.defaults()
	if cfg.RekeyAfterTime != defaultRekeyAfterTime {
		t.Errorf("default RekeyAfterTime = %v, want %v", cfg.RekeyAfterTime, defaultRekeyAfterTime)
	}
}

// TestDialConfigCustomRekeyAfterTimePreserved verifies that an explicitly set
// RekeyAfterTime is not overwritten by defaults().
func TestDialConfigCustomRekeyAfterTimePreserved(t *testing.T) {
	const custom = 30 * time.Second
	cfg := DialConfig{RekeyAfterTime: custom}
	cfg.defaults()
	if cfg.RekeyAfterTime != custom {
		t.Errorf("RekeyAfterTime after defaults() = %v, want %v", cfg.RekeyAfterTime, custom)
	}
}

// TestDefaultRekeyAfterTimeLessThanSessionTimeout verifies the invariant that
// the default rekey threshold is strictly less than the session timeout, leaving
// a window for the new handshake to complete before the old session expires.
func TestDefaultRekeyAfterTimeLessThanSessionTimeout(t *testing.T) {
	if defaultRekeyAfterTime >= sessionTimeout {
		t.Errorf("defaultRekeyAfterTime (%v) must be less than sessionTimeout (%v)",
			defaultRekeyAfterTime, sessionTimeout)
	}
}
