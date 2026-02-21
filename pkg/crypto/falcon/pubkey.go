package fndsa

import "errors"

// PublicKeyFromSecretKey derives the verifying (public) key from a signing
// (secret) key. It accepts keys of any valid degree (logn 2 to 10).
func PublicKeyFromSecretKey(skey []byte) ([]byte, error) {
	if len(skey) == 0 {
		return nil, errors.New("invalid signing key")
	}
	head := skey[0]
	if (head & 0xF0) != 0x50 {
		return nil, errors.New("invalid signing key")
	}
	logn := uint(head & 0x0F)
	if logn < 2 || logn > 10 {
		return nil, errors.New("invalid signing key")
	}
	if len(skey) != SigningKeySize(logn) {
		return nil, errors.New("invalid signing key")
	}

	// Decode f and g from the signing key. F follows but is not needed
	// for public key derivation.
	n := 1 << logn
	f := make([]int8, n)
	g := make([]int8, n)
	off := 1
	j, err := trim_i8_decode(logn, skey[off:], f, nbits_fg(logn))
	if err != nil {
		return nil, err
	}
	off += j
	if _, err = trim_i8_decode(logn, skey[off:], g, nbits_fg(logn)); err != nil {
		return nil, err
	}

	// Compute h = g/f mod X^n+1 mod q.
	t0 := make([]uint16, n)
	t1 := make([]uint16, n)
	mqpoly_small_to_int(logn, g, t0)
	mqpoly_small_to_int(logn, f, t1)
	mqpoly_int_to_ntt(logn, t0)
	mqpoly_int_to_ntt(logn, t1)
	if !mqpoly_div_ntt(logn, t0, t1) {
		return nil, errors.New("invalid signing key: f is not invertible")
	}
	mqpoly_ntt_to_int(logn, t0)
	mqpoly_int_to_ext(logn, t0)

	vkey := make([]byte, VerifyingKeySize(logn))
	vkey[0] = byte(0x00 + logn)
	modq_encode(logn, t0, vkey[1:])
	return vkey, nil
}
