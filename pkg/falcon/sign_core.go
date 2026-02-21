package fndsa

import (
	"crypto"
	sha3 "golang.org/x/crypto/sha3"
)

// Given f, g, F and G, return the basis [[g, -f], [G, -F]] in FFT
// format (b00, b01, b10 and b11, in that order, are written in the
// destination).
func basis_to_FFT(logn uint,
	f []int8, g []int8, F []int8, G []int8, dst []f64) {

	n := 1 << logn
	b00 := dst[:n]
	b01 := dst[n : n*2]
	b10 := dst[n*2 : n*3]
	b11 := dst[n*3 : n*4]
	fpoly_set_small(logn, b01, f)
	fpoly_set_small(logn, b00, g)
	fpoly_set_small(logn, b11, F)
	fpoly_set_small(logn, b10, G)
	fpoly_FFT(logn, b01)
	fpoly_FFT(logn, b00)
	fpoly_FFT(logn, b11)
	fpoly_FFT(logn, b10)
	fpoly_neg(logn, b01)
	fpoly_neg(logn, b11)
}

// Internal signing function. The complete signing key (f,g,F,G) is
// provided, as well as the hashed verifying key, data to sign (context,
// id, hash value), the random seed to work on, the signature
// output buffer, and the temporary areas. The signature buffer has been
// verified to be large enough. The temporary areas are large enough.
//
// Temporary area sizes:
//
//	tmp_i16   n elements
//	tmp_u16   n elements
//	tmp_f64   9*n elements
//
// An error can be returned if the hash identifier is unrecognized or if
// the context string is too large.
func sign_core(logn uint,
	f []int8, g []int8, F []int8, G []int8,
	hashed_vk []byte, ctx DomainContext, id crypto.Hash, data []byte,
	seed []byte, sig []byte,
	tmp_i16 []int16, tmp_u16 []uint16, tmp_f64 []f64) error {

	n := 1 << logn
	sh := sha3.NewShake256()
	hm := tmp_u16
	s2 := tmp_i16
	sig = sig[:SignatureSize(logn)]

	for counter := 0; ; counter++ {
		// Generate the nonce and sub-seed. Note that we regenerate the
		// nonce at each iteration (the original Falcon algorithm did not;
		// regenerating the nonce cannot induce weaknesses, and helps with
		// provability). Since we work over a provided seed, we use
		// SHAKE256 over the concatenation of the seed and the loop counter
		// to get 96 bytes of output.
		sh.Reset()
		sh.Write(seed)
		var cbuf [4]byte
		cbuf[0] = uint8(counter)
		cbuf[1] = uint8(counter >> 8)
		cbuf[2] = uint8(counter >> 16)
		cbuf[3] = uint8(counter >> 24)
		sh.Write(cbuf[:])
		var nonce [40]byte
		var subseed [56]byte
		sh.Read(nonce[:])
		sh.Read(subseed[:])

		// Hash the message into a polynomial.
		err := hash_to_point(logn, nonce[:], hashed_vk, ctx, id, data, hm)
		if err != nil {
			return err
		}

		// Create new sampler.
		ss := newSampler(logn, subseed[:])

		// Compute the lattice basis B = [[g, -f], [G, -F]] in FFT
		// representation, then compute the Gram matrix G = B*adj(B):
		//    g00 = b00*adj(b00) + b01*adj(b01)
		//    g01 = b00*adj(b10) + b01*adj(b11)
		//    g10 = b10*adj(b00) + b11*adj(b01)
		//    g11 = b10*adj(b10) + b11*adj(b11)
		// Note that g10 = adj(g01). For historical reasons, this
		// implementation keeps g01, i.e. the "upper triangle",
		// omitting g10.
		// We want the following layout:
		//    g00 g01 g11 b11 b01
		basis_to_FFT(logn, f, g, F, G, tmp_f64)
		b00 := tmp_f64[:n]
		b01 := tmp_f64[n : n*2]
		b10 := tmp_f64[n*2 : n*3]
		b11 := tmp_f64[n*3 : n*4]
		t0 := tmp_f64[n*4 : n*5]
		copy(t0, b01)
		fpoly_gram_fft(logn, b00, b01, b10, b11)

		// Layout:
		//    g00 g01 g11 b11 b01 t0 t1
		g00 := b00
		g01 := b01
		g11 := b10
		b01 = t0
		t0 = tmp_f64[n*5 : n*6]
		t1 := tmp_f64[n*6 : n*7]

		// Set the target [t0,t1] to [hm,0], then apply the lattice
		// basis to obtain the real target vector (after normalization
		// with regard to the modulus q).
		fpoly_apply_basis(logn, t0, t1, b01, b11, hm)

		// We can now discard b01 and b11; we move back [t0,t1].
		copy(tmp_f64[n*3:n*5], tmp_f64[n*5:n*7])
		t0 = tmp_f64[n*3 : n*4]
		t1 = tmp_f64[n*4 : n*5]

		// Layout:
		//    g00 g01 g11 t0 t1
		// We now do the Fast Fourier sampling.
		ss.ffsamp_fft(t0, t1, g00, g01, g11, tmp_f64[n*5:])

		// Rearrange layout back to:
		//    b00 b01 b10 b11 t0 t1
		copy(tmp_f64[n*4:n*6], tmp_f64[n*3:n*5])
		basis_to_FFT(logn, f, g, F, G, tmp_f64[:n*4])
		b00 = tmp_f64[:n]
		b01 = tmp_f64[n : n*2]
		b10 = tmp_f64[n*2 : n*3]
		b11 = tmp_f64[n*3 : n*4]
		t0 = tmp_f64[n*4 : n*5]
		t1 = tmp_f64[n*5 : n*6]
		tx := tmp_f64[n*6 : n*7]
		ty := tmp_f64[n*7 : n*8]

		// Get the lattice point corresponding to the sampled
		// vector.
		copy(tx, t0)
		copy(ty, t1)
		fpoly_mul_fft(logn, tx, b00)
		fpoly_mul_fft(logn, ty, b10)
		fpoly_add(logn, tx, ty)
		copy(ty, t0)
		fpoly_mul_fft(logn, ty, b01)
		copy(t0, tx)
		fpoly_mul_fft(logn, t1, b11)
		fpoly_add(logn, t1, ty)
		fpoly_iFFT(logn, t0)
		fpoly_iFFT(logn, t1)

		// We compute s1, then s2 into buffer s2 (s1 is not
		// retained). We accumulate their squared norm in sqn,
		// with an "overflow" flag in ng.
		sqn := uint32(0)
		ng := uint32(0)
		for i := 0; i < n; i++ {
			zu := hm[i] - uint16(f64_rint(t0[i]))
			z := int32(int16(zu))
			sqn += uint32(z * z)
			ng |= sqn
		}
		for i := 0; i < n; i++ {
			zu := -uint16(f64_rint(t1[i]))
			z := int32(int16(zu))
			sqn += uint32(z * z)
			ng |= sqn
			s2[i] = int16(z)
		}

		// If the squared norm exceeds 2^31-1, then at some point
		// the high bit of ng was set, which we use to saturate
		// the squared norm to 2^32-1. If the squared norm is
		// unacceptable, then we loop.
		sqn |= uint32(int32(ng) >> 31)
		if !mqpoly_sqnorm_is_acceptable(logn, sqn) {
			continue
		}

		// We have a candidate signature; we must encode it. This
		// may fail, if the signature cannot be encoded in the
		// target size.
		if comp_encode(logn, s2, sig[41:]) {
			// Success!
			sig[0] = byte(0x30 + logn)
			copy(sig[1:41], nonce[:])
			return nil
		}
	}
}
