package fndsa

import (
	"crypto"
	"crypto/rand"
	"errors"
	sha3 "golang.org/x/crypto/sha3"
	"io"
)

// Sign a message using a given signing key.
//
//	- rng is the random source to use (nil to use the OS RNG)
//	- skey is the signing key (private)
//	- ctx is the domain separation context
//	- id is the pre-hash function identifier (0 if no pre-hashing)
//	- data is pre-hashed message (message itself if no pre-hashing)
//
// Using the OS RNG (i.e. setting rng to nil) is recommended. If an
// explicit random source is provided, then the caller MUST make sure that
// it provides sufficient entropy.
// This function will reject any attempt at signing with a key using a
// non-standard degree; it will accept only the standard degrees (512
// and 1024).
func Sign(rng io.Reader, skey []byte,
	ctx DomainContext, id crypto.Hash, data []byte) ([]byte, error) {

	return sign_inner(9, 10, rng, skey, ctx, id, data)
}

// Similar to [Sign], except that this function accepts only the non-standard
// weak degrees 4 to 256, which are meant for research and tests.
func SignWeak(rng io.Reader, skey []byte,
	ctx DomainContext, id crypto.Hash, data []byte) ([]byte, error) {

	return sign_inner(2, 8, rng, skey, ctx, id, data)
}

// Inner signature function.
func sign_inner(logn_min uint, logn_max uint, rng io.Reader, skey []byte,
	ctx DomainContext, id crypto.Hash, data []byte) ([]byte, error) {

	// Get a random 40-byte seed from the provided RNG.
	var seed [40]byte
	if rng == nil {
		rng = rand.Reader
	}
	_, err := io.ReadFull(rng, seed[:])
	if err != nil {
		return nil, err
	}

	return sign_inner_seeded(logn_min, logn_max, seed[:], skey, ctx, id, data)
}

// Inner signature function with an explicit seed; this is used for
// reproducible test vectors.
func sign_inner_seeded(logn_min uint, logn_max uint, seed []byte, skey []byte,
	ctx DomainContext, id crypto.Hash, data []byte) ([]byte, error) {

	// Get degree from key.
	if len(skey) == 0 {
		return nil, errors.New("Invalid private key")
	}
	head1 := skey[0]
	if (head1 & 0xF0) != 0x50 {
		return nil, errors.New("Invalid private key")
	}
	logn := uint(head1 & 0x0F)
	if logn < logn_min || logn > logn_max {
		return nil, errors.New("Invalid private key")
	}
	if len(skey) != SigningKeySize(logn) {
		return nil, errors.New("Invalid private key")
	}

	// Decode key, yielding f, g and F.
	n := 1 << logn
	f := make([]int8, n)
	g := make([]int8, n)
	F := make([]int8, n)
	off := 1
	j, err := trim_i8_decode(logn, skey[off:], f, nbits_fg(logn))
	if err != nil {
		return nil, err
	}
	off += j
	j, err = trim_i8_decode(logn, skey[off:], g, nbits_fg(logn))
	if err != nil {
		return nil, err
	}
	off += j
	_, err = trim_i8_decode(logn, skey[off:], F, 8)
	if err != nil {
		return nil, err
	}

	// Recompute G and the public polynomial h:
	//    h = g/f mod X^n+1 mod q
	//    G = h*F mod X^n+1 mod q
	// We use h to reproduce the verifying key, which we hash.
	G := make([]int8, n)

	t0 := make([]uint16, n)
	t1 := make([]uint16, n)
	// t0 <- h = g/f
	mqpoly_small_to_int(logn, g, t0)
	mqpoly_small_to_int(logn, f, t1)
	mqpoly_int_to_ntt(logn, t0)
	mqpoly_int_to_ntt(logn, t1)
	if !mqpoly_div_ntt(logn, t0, t1) {
		// f is not invertible; the key is not valid
		return nil, errors.New("Invalid signing key (f not invertible)")
	}
	// t1 <- G = h*F
	mqpoly_small_to_int(logn, F, t1)
	mqpoly_int_to_ntt(logn, t1)
	mqpoly_mul_ntt(logn, t1, t0)
	mqpoly_ntt_to_int(logn, t1)
	if !mqpoly_int_to_small(logn, t1, G) {
		// coefficients of G are out-of-range
		return nil, errors.New("Invalid signing key (G is out-of-range)")
	}
	// t0 contains h (in ntt representation), we encode and hash
	// the verifying key.
	mqpoly_ntt_to_int(logn, t0)
	mqpoly_int_to_ext(logn, t0)
	vrfy_key := make([]byte, VerifyingKeySize(logn))
	vrfy_key[0] = byte(0x00 + logn)
	_ = modq_encode(logn, t0, vrfy_key[1:])
	var hashed_vk [64]byte
	sh := sha3.NewShake256()
	sh.Write(vrfy_key[:])
	sh.Read(hashed_vk[:])

	// We can now proceed with the actual signing.
	tmp_i16 := make([]int16, n)
	tmp_u16 := t0
	tmp_f64 := make([]f64, n*9)
	sig := make([]byte, SignatureSize(logn))
	err = sign_core(logn, f, g, F, G, hashed_vk[:], ctx, id, data,
		seed, sig, tmp_i16, tmp_u16, tmp_f64)
	if err != nil {
		return nil, err
	}

	return sig, nil
}
