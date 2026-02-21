package fndsa

import (
	"crypto"
)

// Verify a FN-DSA signature.
//
//	- vkey is the verifying key (public)
//	- ctx is the domain-separation context string
//	- id identifies the pre-hash function (0 for raw message)
//	- data is the pre-hashed message (or message itself if id is zero)
//	- sig is the signature to verify
//
// Returned value is true for a valid signature, false otherwise. If the
// key cannot be decoded, then false is returned. This function accepts
// only the standard, secure degrees (512 and 1024); if the key uses a
// non-standard degree, then false is returned systematically.
func Verify(vkey []byte,
	ctx DomainContext, id crypto.Hash, data []byte, sig []byte) bool {

	return verify_inner(9, 10, vkey, ctx, id, data, sig)
}

// Verify a FN-DSA signature (weak keys). This function acts like
// [Verify], except that it accepts to use only keys with weak degrees
// (4 to 256, i.e. logn = 2 to 8). Such keys are meant for research and
// test purposes only.
func VerifyWeak(vkey []byte,
	ctx DomainContext, id crypto.Hash, data []byte, sig []byte) bool {

	return verify_inner(2, 8, vkey, ctx, id, data, sig)
}

// Inner verification function.
func verify_inner(logn_min uint, logn_max uint, vkey []byte,
	ctx DomainContext, id crypto.Hash, data []byte, sig []byte) bool {

	// Check degrees of both key and signature, and lengths.
	if len(vkey) == 0 || len(sig) == 0 {
		return false
	}
	head1 := vkey[0]
	head2 := sig[0]
	if (head1&0xF0) != 0x00 || (head2&0xF0) != 0x30 {
		return false
	}
	logn := uint(head1 & 0x0F)
	if logn != uint(head2&0x0F) {
		return false
	}
	if logn < logn_min || logn > logn_max {
		return false
	}
	if len(vkey) != VerifyingKeySize(logn) || len(sig) != SignatureSize(logn) {
		return false
	}

	// Allocate the temporary buffers and decode the key and the signature.
	// Key h goes into t1.
	n := 1 << logn
	s2 := make([]int16, n)
	t1 := make([]uint16, n)
	t2 := make([]uint16, n)
	if _, err := modq_decode(logn, vkey[1:], t1); err != nil {
		return false
	}
	if err := comp_decode(logn, sig[41:], s2); err != nil {
		return false
	}
	nonce := sig[1:41]

	// norm2 <- squared norm of s2
	norm2 := signed_poly_sqnorm(logn, s2)

	// t1 <- s2*h ("int" format)
	mqpoly_ext_to_int(logn, t1)
	mqpoly_int_to_ntt(logn, t1)
	mqpoly_signed_to_int(logn, s2, t2)
	mqpoly_int_to_ntt(logn, t2)
	mqpoly_mul_ntt(logn, t1, t2)
	mqpoly_ntt_to_int(logn, t1)

	// t2 <- c = hashed message ("int" format)
	hvk := hash_verifying_key(vkey)
	hash_to_point(logn, nonce, hvk[:], ctx, id, data, t2)
	mqpoly_ext_to_int(logn, t2)

	// t2 <- s1 = c - s2*h ("int" format)
	mqpoly_sub_int(logn, t2, t1)

	// norm1 <- squared norm of s1
	norm1 := mqpoly_sqnorm(logn, t2)

	// Signature is acceptable if the total squared norm of (s1,s2) is
	// low enough. We must take care of not overflowing.
	return norm1 < -norm2 && mqpoly_sqnorm_is_acceptable(logn, norm1+norm2)
}
