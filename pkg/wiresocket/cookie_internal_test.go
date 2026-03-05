package wiresocket

import (
	"testing"
)

// TestCookieReplyRoundtrip verifies that BuildCookieReply and ConsumeCookieReply
// roundtrip correctly: the decrypted cookie matches the one the manager would
// compute for the same address.
func TestCookieReplyRoundtrip(t *testing.T) {
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	cm := newCookieManager(kp.Public)

	const addr = "192.0.2.1:12345"
	var mac1 [16]byte
	mac1[0] = 0xAA
	mac1[1] = 0xBB

	reply, err := cm.BuildCookieReply(42, mac1, addr)
	if err != nil {
		t.Fatalf("BuildCookieReply: %v", err)
	}
	if reply.ReceiverIndex != 42 {
		t.Errorf("ReceiverIndex = %d, want 42", reply.ReceiverIndex)
	}

	cookie, err := ConsumeCookieReply(reply, mac1)
	if err != nil {
		t.Fatalf("ConsumeCookieReply: %v", err)
	}

	// The cookie must be non-zero (the server actually generated one).
	var zero [16]byte
	if cookie == zero {
		t.Error("ConsumeCookieReply returned all-zero cookie")
	}

	// Recompute the expected cookie from the manager and compare.
	expected := cm.makeCookie(addr)
	if cookie != expected {
		t.Error("decrypted cookie does not match cookieManager.makeCookie")
	}
}

// TestCookieReplyWrongMAC1 verifies that ConsumeCookieReply fails to decrypt
// when the wrong mac1 is provided (authentication mismatch).
func TestCookieReplyWrongMAC1(t *testing.T) {
	kp, _ := GenerateKeypair()
	cm := newCookieManager(kp.Public)

	var mac1 [16]byte
	mac1[0] = 0x01
	reply, err := cm.BuildCookieReply(1, mac1, "127.0.0.1:1000")
	if err != nil {
		t.Fatal(err)
	}

	var wrongMAC1 [16]byte
	wrongMAC1[0] = 0xFF
	_, err = ConsumeCookieReply(reply, wrongMAC1)
	if err == nil {
		t.Error("ConsumeCookieReply succeeded with wrong mac1")
	}
}

// TestCookieDifferentAddresses verifies that cookies for different addresses
// are different.
func TestCookieDifferentAddresses(t *testing.T) {
	kp, _ := GenerateKeypair()
	cm := newCookieManager(kp.Public)

	c1 := cm.makeCookie("10.0.0.1:5000")
	c2 := cm.makeCookie("10.0.0.2:5000")
	if c1 == c2 {
		t.Error("different addresses produced identical cookies")
	}
}

// TestCookieSameAddressSameSecret verifies that two calls to makeCookie with
// the same address and the same (non-rotated) secret produce the same cookie.
func TestCookieSameAddressSameSecret(t *testing.T) {
	kp, _ := GenerateKeypair()
	cm := newCookieManager(kp.Public)

	addr := "172.16.0.5:9000"
	c1 := cm.makeCookie(addr)
	c2 := cm.makeCookie(addr)
	if c1 != c2 {
		t.Error("same address produced different cookies with same secret")
	}
}

// TestComputeMAC2 verifies that computeMAC2 produces different results for
// different cookies and different messages.
func TestComputeMAC2(t *testing.T) {
	var cookie1, cookie2 [16]byte
	cookie1[0] = 1
	cookie2[0] = 2
	msg := []byte("handshake body bytes")

	m1 := computeMAC2(cookie1, msg)
	m2 := computeMAC2(cookie2, msg)
	if m1 == m2 {
		t.Error("computeMAC2: different cookies produced same MAC2")
	}

	// Same cookie, different message.
	m3 := computeMAC2(cookie1, []byte("different body"))
	if m1 == m3 {
		t.Error("computeMAC2: different messages produced same MAC2")
	}
}

// TestCookieManagerDifferentServers verifies that two cookie managers (with
// different static keys) produce different cookies for the same address.
func TestCookieManagerDifferentServers(t *testing.T) {
	kp1, _ := GenerateKeypair()
	kp2, _ := GenerateKeypair()
	cm1 := newCookieManager(kp1.Public)
	cm2 := newCookieManager(kp2.Public)

	addr := "10.0.0.1:8080"
	c1 := cm1.makeCookie(addr)
	c2 := cm2.makeCookie(addr)
	if c1 == c2 {
		t.Error("different servers produced identical cookies for the same address")
	}
}
