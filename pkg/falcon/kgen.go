package fndsa

import (
	"crypto/rand"
	"errors"
	"io"
)

// Generate a new key pair.
//
//	- logn is the degree to use (logarithmic, 2 to 10).
//	- rng is random source to use (nil to use the OS RNG).
//
// Output is the new key pair (signing and verifying keys, both encoded).
// An error is reported if the requested degree is invalid, or if the
// random source fails. Standard secure degrees correspond to logn equal to
// 9 (512) or 10 (1024); lower values do not provide adequate security and
// are meant for research and test purposes only.
func KeyGen(logn uint, rng io.Reader) (skey []byte, vkey []byte, err error) {
	skey = nil
	vkey = nil
	if logn < 2 || logn > 10 {
		err = errors.New("invalid degree")
		return
	}
	if rng == nil {
		rng = rand.Reader
	}
	var seed [32]byte
	_, err = io.ReadFull(rng, seed[:])
	if err != nil {
		return
	}

	// Degree has been checked and a 32-byte seed has been obtained; now,
	// the process cannot fail.
	n := 1 << logn
	f := make([]int8, n)
	g := make([]int8, n)
	F := make([]int8, n)
	G := make([]int8, n)
	tmp := make([]uint32, 6*n)
	tmp_fxr := make([]fxr, 5*(n>>1))
	tmp_u16 := make([]uint16, 2*n)
	keygen_inner(logn, seed[:], f, g, F, G, tmp, tmp_fxr, tmp_u16)
	skey, vkey = encode_keypair(logn, f, g, F, G, tmp_u16)
	return
}

// Inner function; logn is assumed to be correct, and the output is
// deterministic for the provided seed.
func keygen_inner(logn uint, seed []byte,
	f []int8, g []int8, F []int8, G []int8,
	tmp []uint32, tmp_fxr []fxr, tmp_u16 []uint16) {

	n := 1 << logn
	pc := newSHAKE256prng(seed)
	for {
		// Sample f and g, both with odd parity.
		sample_f(logn, pc, f)
		sample_f(logn, pc, g)

		// Ensure that ||(g, -f)|| < 1.17*sqrt(q),
		// i.e. that ||(g, -f)||^2 < (1.17^2)*q = 16822.4121
		sn := int32(0)
		for i := 0; i < n; i++ {
			xf := int32(f[i])
			xg := int32(g[i])
			sn += xf*xf + xg*xg
		}
		if sn >= 16823 {
			continue
		}

		// f must be invertible modulo X^n+1 modulo q.
		if !mqpoly_is_invertible(logn, f, tmp_u16) {
			continue
		}

		// (f,g) must have an acceptable orthogonalized norm.
		if !check_ortho_norm(logn, f, g, tmp_fxr) {
			continue
		}

		// Try to solve the NTRU equation.
		if !solve_NTRU(logn, f, g, F, G, tmp, tmp_fxr) {
			continue
		}
		break
	}
}

// Encode the private and public keys, given the four secret polynomials.
// tmp_u16[] shall have size at least 2*n elements.
func encode_keypair(logn uint, f []int8, g []int8,
	F []int8, G []int8, tmp_u16 []uint16) (skey []byte, vkey []byte) {

	n := 1 << logn

	// We have f, g, F and G, we can recompute the public key h = g/f mod q,
	// and encode both keys.
	skey = make([]byte, SigningKeySize(logn))
	nbits := nbits_fg(logn)
	skey[0] = byte(0x50 + logn)
	j := 1
	j += trim_i8_encode(logn, f, nbits, skey[j:])
	j += trim_i8_encode(logn, g, nbits, skey[j:])
	_ = trim_i8_encode(logn, F, 8, skey[j:])

	vkey = make([]byte, VerifyingKeySize(logn))
	vkey[0] = byte(0x00 + logn)
	h := tmp_u16[:n]
	t1 := tmp_u16[n:]
	mqpoly_small_to_int(logn, g, h)
	mqpoly_small_to_int(logn, f, t1)
	mqpoly_int_to_ntt(logn, h)
	mqpoly_int_to_ntt(logn, t1)
	mqpoly_div_ntt(logn, h, t1)
	mqpoly_ntt_to_int(logn, h)
	mqpoly_int_to_ext(logn, h)
	_ = modq_encode(logn, h, vkey[1:])
	return
}
