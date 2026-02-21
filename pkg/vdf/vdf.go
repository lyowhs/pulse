// Package vdf implements the Wesolowski Verifiable Delay Function (VDF) over
// an RSA group.
//
// A VDF is a function that requires a prescribed number of sequential steps to
// evaluate, yet produces a short proof that can be verified in far less time.
// This implementation uses repeated squaring in Z/NZ as the delay primitive and
// Wesolowski's proof system for O(log T) verification.
//
// Security requires that the factorisation of N remains unknown. Use
// [DefaultModulus] for a production modulus (the RSA-2048 challenge number,
// whose factorisation has never been found) or [GenerateModulus] for testing.
package vdf

import (
	"crypto/sha256"
	"encoding/binary"
	"math/big"
)

var two = big.NewInt(2)

// Proof holds the output and witness of a VDF evaluation.
type Proof struct {
	// Output is y = x^(2^Iterations) mod N.
	Output []byte
	// Pi is the Wesolowski witness π = x^(⌊2^Iterations / l⌋) mod N.
	Pi []byte
}

// VDF is a Verifiable Delay Function over the RSA group Z/NZ, using
// Wesolowski proofs.
type VDF struct {
	// N is the RSA modulus. Its factorisation must remain unknown — knowing
	// φ(N) allows the delay to be shortcut via fast exponentiation.
	N *big.Int
}

// New creates a VDF over the RSA group with the given modulus.
func New(n *big.Int) *VDF {
	return &VDF{N: new(big.Int).Set(n)}
}

// Evaluate computes y = x^(2^iterations) mod N and produces a Wesolowski
// proof that the computation was performed honestly.
//
// The input bytes are hashed to a group element before use.
// Complexity: O(iterations) sequential squarings (two passes).
func (v *VDF) Evaluate(input []byte, iterations uint64) Proof {
	x := hashToGroupElement(input, v.N)

	// Pass 1: y = x^(2^T) mod N.
	y := new(big.Int).Set(x)
	for range iterations {
		y.Mul(y, y)
		y.Mod(y, v.N)
	}

	// Fiat-Shamir challenge prime derived from (x, y, T).
	l := hashToPrime(x, y, iterations)

	// Pass 2: π = x^(⌊2^T/l⌋) mod N via Wesolowski's long-division algorithm.
	pi := computePi(x, v.N, iterations, l)

	return Proof{
		Output: y.Bytes(),
		Pi:     pi.Bytes(),
	}
}

// Verify checks a VDF proof without repeating the full computation.
// Complexity: two modular exponentiations, O(log T) group operations.
//
// Returns false for an invalid or malformed proof.
func (v *VDF) Verify(input []byte, iterations uint64, p Proof) bool {
	if len(p.Output) == 0 || len(p.Pi) == 0 {
		return false
	}

	x := hashToGroupElement(input, v.N)
	y := new(big.Int).SetBytes(p.Output)
	pi := new(big.Int).SetBytes(p.Pi)

	l := hashToPrime(x, y, iterations)

	// r = 2^T mod l.
	r := new(big.Int).Exp(two, new(big.Int).SetUint64(iterations), l)

	// Proof is valid iff π^l · x^r ≡ y (mod N).
	lhs := new(big.Int).Mul(
		new(big.Int).Exp(pi, l, v.N),
		new(big.Int).Exp(x, r, v.N),
	)
	lhs.Mod(lhs, v.N)

	return lhs.Cmp(y) == 0
}

// hashToGroupElement maps arbitrary bytes to a non-zero element of Z/NZ
// via SHA-256.
func hashToGroupElement(input []byte, n *big.Int) *big.Int {
	h := sha256.Sum256(input)
	x := new(big.Int).SetBytes(h[:])
	x.Mod(x, n)
	if x.Sign() == 0 {
		x.SetInt64(1)
	}
	return x
}

// hashToPrime derives a challenge prime from x, y, and the iteration count
// using the Fiat-Shamir heuristic. It hashes the inputs with SHA-256 and
// finds the next odd prime at or above the resulting value.
func hashToPrime(x, y *big.Int, iterations uint64) *big.Int {
	h := sha256.New()
	h.Write(x.Bytes())
	h.Write(y.Bytes())
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], iterations)
	h.Write(b[:])

	candidate := new(big.Int).SetBytes(h.Sum(nil))
	candidate.SetBit(candidate, 0, 1) // ensure odd
	for !candidate.ProbablyPrime(20) {
		candidate.Add(candidate, two)
	}
	return candidate
}

// computePi computes the Wesolowski witness π = x^(⌊2^T/l⌋) mod N.
//
// At each of the T steps, a running remainder r is doubled. When r exceeds l
// the quotient increments by one, which is accumulated into π as a factor of
// x. After T steps π = x^(⌊2^T/l⌋) mod N and r = 2^T mod l.
func computePi(x, n *big.Int, iterations uint64, l *big.Int) *big.Int {
	pi := big.NewInt(1)
	r := big.NewInt(1)

	for range iterations {
		r.Mul(r, two)
		b := new(big.Int).Div(r, l) // b ∈ {0,1} since r < l before doubling
		r.Mod(r, l)

		pi.Mul(pi, pi)
		pi.Mod(pi, n)
		if b.Sign() > 0 {
			pi.Mul(pi, x)
			pi.Mod(pi, n)
		}
	}
	return pi
}
