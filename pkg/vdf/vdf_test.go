package vdf

import (
	"crypto/rand"
	"math/big"
	"testing"
)

// testVDF returns a VDF over a fresh 512-bit RSA modulus (p*q) generated
// directly from random primes, bypassing crypto/rsa's minimum-size check.
// 512 bits is sufficient for correctness testing.
func testVDF(t *testing.T) *VDF {
	t.Helper()
	p, err := rand.Prime(rand.Reader, 256)
	if err != nil {
		t.Fatalf("generate prime p: %v", err)
	}
	q, err := rand.Prime(rand.Reader, 256)
	if err != nil {
		t.Fatalf("generate prime q: %v", err)
	}
	return New(new(big.Int).Mul(p, q))
}

func TestEvaluateVerify(t *testing.T) {
	v := testVDF(t)
	proof := v.Evaluate([]byte("hello"), 1000)
	if !v.Verify([]byte("hello"), 1000, proof) {
		t.Fatal("valid proof did not verify")
	}
}

func TestVerifyRejectsTamperedOutput(t *testing.T) {
	v := testVDF(t)
	proof := v.Evaluate([]byte("hello"), 500)

	proof.Output[0] ^= 0xFF

	if v.Verify([]byte("hello"), 500, proof) {
		t.Fatal("tampered output should not verify")
	}
}

func TestVerifyRejectsTamperedPi(t *testing.T) {
	v := testVDF(t)
	proof := v.Evaluate([]byte("hello"), 500)

	proof.Pi[0] ^= 0xFF

	if v.Verify([]byte("hello"), 500, proof) {
		t.Fatal("tampered witness should not verify")
	}
}

func TestVerifyRejectsDifferentInput(t *testing.T) {
	v := testVDF(t)
	proof := v.Evaluate([]byte("hello"), 500)

	if v.Verify([]byte("world"), 500, proof) {
		t.Fatal("proof should not verify against a different input")
	}
}

func TestVerifyRejectsDifferentIterations(t *testing.T) {
	v := testVDF(t)
	proof := v.Evaluate([]byte("hello"), 500)

	if v.Verify([]byte("hello"), 501, proof) {
		t.Fatal("proof should not verify against a different iteration count")
	}
}

func TestDefaultModulus(t *testing.T) {
	n := DefaultModulus()
	if n.BitLen() != 2048 {
		t.Fatalf("expected 2048-bit modulus, got %d bits", n.BitLen())
	}
}
