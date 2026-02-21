package fndsa

// Set polynomial d by reducing small polynomial f modulo p.
func poly_mp_set_small(logn uint, d []uint32, f []int8, p uint32) {
	n := 1 << logn
	for i := 0; i < n; i++ {
		d[i] = mp_set(int32(f[i]), p)
	}
}

// Convert a polynomial in one-word normal representation (signed) into RNS
// modulo the single prime p.
func poly_mp_set(logn uint, f []uint32, p uint32) {
	n := 1 << logn
	for i := 0; i < n; i++ {
		x := f[i]
		x |= (x & 0x40000000) << 1
		f[i] = mp_set(int32(x), p)
	}
}

// Convert a polynomial in one-word normal representation (signed) into RNS
// modulo the single prime p.
func poly_mp_norm(logn uint, f []uint32, p uint32) {
	n := 1 << logn
	for i := 0; i < n; i++ {
		f[i] = uint32(mp_norm(f[i], p)) & 0x7FFFFFFF
	}
}

// Convert a polynomial s to small integers f. Source values are
// supposed to be normalized (signed). Returned value is false if any of the
// coefficients exceeds the provided limit (in absolute value); on
// success, true is returned.
//
// In case of failure, the function returns earlier; this does not break
// constant-time discipline as long as a failure implies that the (f,g)
// polynomials are discarded.
func poly_big_to_small(logn uint, d []int8, s []uint32, lim int32) bool {
	n := 1 << logn
	for i := 0; i < n; i++ {
		x := s[i]
		x |= (x & 0x40000000) << 1
		z := int32(x)
		if z < -lim || z > lim {
			return false
		}
		d[i] = int8(z)
	}
	return true
}

// Count of leading zeros in a 32-bit word (which may be zero).
func lzcnt32(x uint32) uint32 {
	y4 := x >> 16
	m4 := (y4 - 1) >> 16
	r := m4 & 0x10
	x3 := y4 | (m4 & x)

	y3 := x3 >> 8
	m3 := (y3 - 1) >> 8
	r |= m3 & 0x08
	x2 := y3 | (m3 & x3)

	y2 := x2 >> 4
	m2 := (y2 - 1) >> 4
	r |= m2 & 0x04
	x1 := y2 | (m2 & x2)

	y1 := x1 >> 2
	m1 := (y1 - 1) >> 2
	r |= m1 & 0x02
	x0 := y1 | (m1 & x1)

	// Value x0 now fits on 2 bits. The length of x0 equals its value,
	// unless it is equal to 3, which only has vlaue 2.
	return r + 2 + ((x0 + 1) >> 2) - x0
}

// Get the maximum bit length of all coefficients of a polynomial. Each
// coefficient has size flen words.
//
// The bit length of a big integer is defined to be the length of the
// minimal binary representation, using two's complement for negative
// values, and excluding the sign bit. This definition implies that
// if x = 2^k, then x has bit length k but -x has bit length k-1. For
// non powers of two, x and -x have the same bit length.
//
// This function is constant-time with regard to coefficient values and
// the returned bit length.
func poly_max_bitlength(logn uint, f []uint32, flen int) uint32 {
	if flen == 0 {
		return 0
	}

	n := 1 << logn
	t := uint32(0)
	tk := uint32(0)
	for i := 0; i < n; i++ {
		// Extend sign bit into a 31-bit mask.
		m := -(f[i+((flen-1)<<logn)] >> 30) & 0x7FFFFFFF

		// Get top non-zero sign-adjusted word, with index.
		c := uint32(0)
		ck := uint32(0)
		for j := 0; j < flen; j++ {
			// sign-adjusted word
			w := f[i+(j<<logn)] ^ m
			nz := ((w - 1) >> 31) - 1
			c ^= nz & (c ^ w)
			ck ^= nz & (ck ^ uint32(j))
		}

		// If ck > tk, or tk == ck but c > t, then (c,ck) must
		// replace (t,tk) as current candidate for top word/index.
		rr := tbmask((tk - ck) | (((tk ^ ck) - 1) & (t - c)))
		t ^= rr & (t ^ c)
		tk ^= rr & (tk ^ ck)
	}

	// Get bit length of the top word (which has been sign-adjusted)
	// and return the result.
	return 31*tk + 32 - lzcnt32(t)
}

// Compute q = x / 31 and r = x % 31 for an unsigned integer x. This
// function is constant-time and works for values x up to 63487 (inclusive).
func divrem31(x uint32) (q uint32, r uint32) {
	q = (x * 67651) >> 21
	r = x - 31*q
	return
}

// Convert a polynomial f to fixed-point approximations d, with scaling.
// For each coefficient x, the computed approximation is x/2^sc.
// This function assumes that |x| < 2^(30+sc). The length of each
// coefficient must be less than 2^24 words.
//
// This function is constant-time with regard to the coefficient values
// and to the scaling factor.
func poly_big_to_fixed(logn uint, d []fxr, f []uint32, flen int, sc uint32) {
	n := 1 << logn
	if flen == 0 {
		for i := 0; i < n; i++ {
			d[i] = 0
		}
		return
	}

	// We split the bit length into sch and scl such that:
	//   sc = 31*sch + scl
	// We also want scl in the 1..31 range, not 0..30. It may happen
	// that sch becomes -1, which will "wrap around" (harmlessly).
	//
	// For each coefficient, we need three words, each with a given
	// left shift (negative for a right shift):
	//    sch-1   1 - scl
	//    sch     32 - scl
	//    sch+1   63 - scl
	sch, scl := divrem31(sc)
	z := (scl - 1) >> 31
	sch -= z
	scl |= 31 & -z

	t0 := (sch - 1) & 0xFFFFFF
	t1 := sch & 0xFFFFFF
	t2 := (sch + 1) & 0xFFFFFF

	for i := 0; i < n; i++ {
		w0 := uint32(0)
		w1 := uint32(0)
		w2 := uint32(0)
		for j := 0; j < flen; j++ {
			w := f[i+(j<<logn)]
			t := uint32(j) & 0xFFFFFF
			w0 |= w & -(((t ^ t0) - 1) >> 31)
			w1 |= w & -(((t ^ t1) - 1) >> 31)
			w2 |= w & -(((t ^ t2) - 1) >> 31)
		}

		// If there were not enough words for the requested
		// scaling, then we must supply copies with the proper
		// sign.
		ws := -(f[i+((flen-1)<<logn)] >> 30) >> 1
		w0 |= ws & -((uint32(flen) - sch) >> 31)
		w1 |= ws & -((uint32(flen) - sch - 1) >> 31)
		w2 |= ws & -((uint32(flen) - sch - 2) >> 31)

		// Assemble the 64-bit value with the shifts. We assume
		// that shifts on 32-bit values are constant-time with
		// regard to the shift count (this should be true on all
		// modern architectures; the last notable arch on which
		// shift timing depended on the count was the Pentium IV).
		//
		// Since the shift count (scl) is guaranteed to be in 1..31,
		// we do not have special cases to handle.
		//
		// We must sign-extend w2 to ensure the sign bit is properly
		// set in the fxr value.
		w2 |= (w2 & 0x40000000) << 1
		xl := (w0 >> (scl - 1)) | (w1 << (32 - scl))
		xh := (w1 >> scl) | (w2 << (31 - scl))
		d[i] = fxr_of_scaled32(uint64(xl) | (uint64(xh) << 32))
	}
}

// Subtract k*f from F, where F, f and k are polynomials modulo X^n+1.
// Coefficients of polynomial k are small _signed_ integers (values in the
// -2^31..+2^31 range, but encoded as uint32) scaled by 2^sc.
//
// This function implements the basic quadratic multiplication algorithm,
// which is efficient in space (no extra buffer needed) but slow at
// high degree.
func poly_sub_scaled(logn uint,
	F []uint32, Flen int, f []uint32, flen int, k []uint32, sc uint32) {

	if flen == 0 {
		return
	}
	sch, scl := divrem31(sc)
	if int(sch) >= Flen {
		return
	}
	b := int(sch) << logn
	Flen -= int(sch)
	n := 1 << logn
	for i := 0; i < n; i++ {
		kf := -int32(k[i])
		c := b + i
		for j := 0; j < n; j++ {
			zint_add_scaled_mul_small(F[c:], Flen, f[j:], flen, n, kf, 0, scl)
			if i+j == n-1 {
				c = b
				kf = -kf
			} else {
				c++
			}
		}
	}
}

// Subtract k*f from F. Coefficients of polynomial k are small _signed_
// integers (values in the -2^31..+2^31 range but encoded as uint32)
// scaled by 2^sc. Polynomial f MUST be in RNS+NTT over flen+1 words
// (even though f itself would fit on flen words); polynomial F MUST be
// in plain representation.
func poly_sub_scaled_ntt(logn uint, F []uint32, Flen int,
	f []uint32, flen int, k []uint32, sc uint32, tmp []uint32) {

	n := 1 << logn
	tlen := flen + 1
	gm := tmp[:n]
	igm := tmp[n : 2*n]
	fk := tmp[2*n : 2*n+(tlen<<logn)]
	t1 := tmp[2*n+(tlen<<logn):]
	sch, scl := divrem31(sc)

	// Compute k*f in fk[], in RNS notation.
	// f is assumed to be already in RNS+NTT over flen+1 words.
	for i := 0; i < tlen; i++ {
		p := primes[i].p
		p0i := primes[i].p0i
		r2 := primes[i].r2
		mp_mkgmigm(logn, gm, igm, primes[i].g, primes[i].ig, p, p0i)
		for j := 0; j < n; j++ {
			t1[j] = mp_set(int32(k[j]), p)
		}
		mp_NTT(logn, t1, gm, p, p0i)

		fs := f[(i << logn):]
		ff := fk[(i << logn):]
		for j := 0; j < n; j++ {
			ff[j] = mp_mmul(mp_mmul(t1[j], fs[j], p, p0i), r2, p, p0i)
		}
		mp_iNTT(logn, ff, igm, p, p0i)
	}

	// Rebuild k*f.
	zint_rebuild_CRT(fk, tlen, n, 1, true, t1)

	// Subtract k*f, scaled, from F.
	for i := 0; i < n; i++ {
		zint_sub_scaled(F[i:], Flen, fk[i:], tlen, n, sch, scl)
	}
}

// depth = 1
// logn = logn_top - depth
// Inputs:
//
//	F, G    polynomials of degree 2^logn, plain integer representation (FGlen)
//	FGlen   size of each coefficient of F and G (must be 1 or 2)
//	f, g    polynomials of degree 2^logn_top, small coefficients
//	k       polynomial of degree 2^logn (plain, 32-bit)
//	sc      scaling logarithm (public value)
//	tmp     temporary with room at least max(FGlen, 2^logn_top) words
//
// Operation:
//
//	F <- F - (2^sc)*k*ft
//	G <- G - (2^sc)*k*gt
//
// with (ft,gt) being the degree-n polynomials corresponding to (f,g)
// It is assumed that the result fits.
//
// WARNING: polynomial k is consumed in the process.
//
// This function uses 3*n words in tmp[]. */
func poly_sub_kfg_scaled_depth1(logn_top uint,
	F []uint32, G []uint32, FGlen int, k []uint32, sc uint32,
	f []int8, g []int8, tmp []uint32) {

	logn := logn_top - 1
	n := 1 << logn
	hn := n >> 1
	gm := tmp[:n]
	t1 := tmp[n : 2*n]
	t2 := tmp[2*n:]

	// Step 1: convert F and G to RNS. Since FGlen is equal to 1 or 2,
	// we do it with some specialized code. We assume that the RNS
	// representation does not lose information (i.e. each signed
	// coefficient is lower than (p0*p1)/2, with FGlen = 2 and the two
	// prime moduli are p0 and p1).
	if FGlen == 1 {
		p := primes[0].p
		for i := 0; i < n; i++ {
			xf := F[i]
			xg := G[i]
			xf |= (xf & 0x40000000) << 1
			xg |= (xg & 0x40000000) << 1
			F[i] = mp_set(int32(xf), p)
			G[i] = mp_set(int32(xg), p)
		}
	} else {
		p0 := primes[0].p
		p0_0i := primes[0].p0i
		z0 := mp_half(primes[0].r2, p0)
		p1 := primes[1].p
		p1_0i := primes[1].p0i
		z1 := mp_half(primes[1].r2, p1)
		for i := 0; i < n; i++ {
			xl := F[i]
			xh := F[i+n] | ((F[i+n] & 0x40000000) << 1)
			yl0 := xl - (p0 & ^tbmask(xl-p0))
			yh0 := mp_set(int32(xh), p0)
			r0 := mp_add(yl0, mp_mmul(yh0, z0, p0, p0_0i), p0)
			yl1 := xl - (p1 & ^tbmask(xl-p1))
			yh1 := mp_set(int32(xh), p1)
			r1 := mp_add(yl1, mp_mmul(yh1, z1, p1, p1_0i), p1)
			F[i] = r0
			F[i+n] = r1

			xl = G[i]
			xh = G[i+n] | ((G[i+n] & 0x40000000) << 1)
			yl0 = xl - (p0 & ^tbmask(xl-p0))
			yh0 = mp_set(int32(xh), p0)
			r0 = mp_add(yl0, mp_mmul(yh0, z0, p0, p0_0i), p0)
			yl1 = xl - (p1 & ^tbmask(xl-p1))
			yh1 = mp_set(int32(xh), p1)
			r1 = mp_add(yl1, mp_mmul(yh1, z1, p1, p1_0i), p1)
			G[i] = r0
			G[i+n] = r1
		}
	}

	// Step 2: for FGlen small primes, convert F and G to RNS+NTT,
	// and subtract (2^sc)*(ft,gt). The (ft,gt) polynomials are computed
	// in RNS+NTT dynamically.
	for i := 0; i < FGlen; i++ {
		p := primes[i].p
		p0i := primes[i].p0i
		r2 := primes[i].r2
		r3 := mp_mmul(r2, r2, p, p0i)
		mp_mkgm(logn, gm, primes[i].g, p, p0i)

		// k <- (2^sc)*k (and into NTT).
		scv := mp_mmul(uint32(1)<<(sc&31), r2, p, p0i)
		for m := sc >> 5; m > 0; m-- {
			scv = mp_mmul(scv, r2, p, p0i)
		}
		for j := 0; j < n; j++ {
			x := mp_set(int32(k[j]), p)
			k[j] = mp_mmul(scv, x, p, p0i)
		}
		mp_NTT(logn, k, gm, p, p0i)

		// Convert F and G to NTT.
		Fu := F[i<<logn:]
		Gu := G[(i << logn):]
		mp_NTT(logn, Fu, gm, p, p0i)
		mp_NTT(logn, Gu, gm, p, p0i)

		// Given the top-level f, we obtain ft = N(f) (the f at
		// depth 1) with:
		//    f = f_e(X^2) + X*f_o(X^2)
		// with f_e and f_o being modulo X^n+1. Then:
		//    N(f) = f_e^2 - X*f_o^2
		// The NTT representation of X is obtained from the gm[] tab:
		//    NTT(X)[2*j + 0] = gm[j + n/2]
		//    NTT(X)[2*j + 1] = -NTT(X)[2*j + 0]
		// Note that the values in gm[] are in Montgomery
		// representation.
		for j := 0; j < n; j++ {
			t1[j] = mp_set(int32(f[(j<<1)+0]), p)
			t2[j] = mp_set(int32(f[(j<<1)+1]), p)
		}
		mp_NTT(logn, t1, gm, p, p0i)
		mp_NTT(logn, t2, gm, p, p0i)
		for j := 0; j < hn; j++ {
			xe0 := t1[(j<<1)+0]
			xe1 := t1[(j<<1)+1]
			xo0 := t2[(j<<1)+0]
			xo1 := t2[(j<<1)+1]
			xv0 := gm[hn+j]
			xv1 := p - xv0
			xe0 = mp_mmul(xe0, xe0, p, p0i)
			xe1 = mp_mmul(xe1, xe1, p, p0i)
			xo0 = mp_mmul(xo0, xo0, p, p0i)
			xo1 = mp_mmul(xo1, xo1, p, p0i)
			xf0 := mp_sub(xe0, mp_mmul(xo0, xv0, p, p0i), p)
			xf1 := mp_sub(xe1, mp_mmul(xo1, xv1, p, p0i), p)

			xkf0 := mp_mmul(mp_mmul(xf0, k[(j<<1)+0], p, p0i), r3, p, p0i)
			xkf1 := mp_mmul(mp_mmul(xf1, k[(j<<1)+1], p, p0i), r3, p, p0i)
			Fu[(j<<1)+0] = mp_sub(Fu[(j<<1)+0], xkf0, p)
			Fu[(j<<1)+1] = mp_sub(Fu[(j<<1)+1], xkf1, p)
		}

		// Same treatment for G and gt.
		for j := 0; j < n; j++ {
			t1[j] = mp_set(int32(g[(j<<1)+0]), p)
			t2[j] = mp_set(int32(g[(j<<1)+1]), p)
		}
		mp_NTT(logn, t1, gm, p, p0i)
		mp_NTT(logn, t2, gm, p, p0i)
		for j := 0; j < hn; j++ {
			xe0 := t1[(j<<1)+0]
			xe1 := t1[(j<<1)+1]
			xo0 := t2[(j<<1)+0]
			xo1 := t2[(j<<1)+1]
			xv0 := gm[hn+j]
			xv1 := p - xv0
			xe0 = mp_mmul(xe0, xe0, p, p0i)
			xe1 = mp_mmul(xe1, xe1, p, p0i)
			xo0 = mp_mmul(xo0, xo0, p, p0i)
			xo1 = mp_mmul(xo1, xo1, p, p0i)
			xg0 := mp_sub(xe0, mp_mmul(xo0, xv0, p, p0i), p)
			xg1 := mp_sub(xe1, mp_mmul(xo1, xv1, p, p0i), p)

			xkg0 := mp_mmul(mp_mmul(xg0, k[(j<<1)+0], p, p0i), r3, p, p0i)
			xkg1 := mp_mmul(mp_mmul(xg1, k[(j<<1)+1], p, p0i), r3, p, p0i)
			Gu[(j<<1)+0] = mp_sub(Gu[(j<<1)+0], xkg0, p)
			Gu[(j<<1)+1] = mp_sub(Gu[(j<<1)+1], xkg1, p)
		}

		// Convert back F and G to RNS.
		mp_mkigm(logn, t1, primes[i].ig, p, p0i)
		mp_iNTT(logn, Fu, t1, p, p0i)
		mp_iNTT(logn, Gu, t1, p, p0i)

		// We replaced k (plain 32-bit) with (2^sc)*k (NTT). We must
		// put it back to its initial value if there should be another
		// iteration.
		if (i + 1) < FGlen {
			mp_iNTT(logn, k, t1, p, p0i)
			scv = uint32(1) << (-sc & 31)
			for m := sc >> 5; m > 0; m-- {
				scv = mp_mmul(scv, 1, p, p0i)
			}
			for j := 0; j < n; j++ {
				k[j] = uint32(mp_norm(mp_mmul(scv, k[j], p, p0i), p))
			}
		}
	}

	// Output F and G are in RNS (non-NTT), but we want plain integers.
	if FGlen == 1 {
		p := primes[0].p
		for i := 0; i < n; i++ {
			F[i] = uint32(mp_norm(F[i], p) & 0x7FFFFFFF)
			G[i] = uint32(mp_norm(G[i], p) & 0x7FFFFFFF)
		}
	} else {
		p0 := primes[0].p
		p1 := primes[1].p
		p1_0i := primes[1].p0i
		s := primes[1].s
		pp := uint64(p0) * uint64(p1)
		hpp := pp >> 1
		for i := 0; i < n; i++ {
			// Apply CRT with two primes on the coefficient of F.
			x0 := F[i]   // mod p0
			x1 := F[i+n] // mod p1
			x0m1 := x0 - (p1 & ^tbmask(x0-p1))
			y := mp_mmul(mp_sub(x1, x0m1, p1), s, p1, p1_0i)
			z := uint64(x0) + uint64(p0)*uint64(y)
			z -= pp & -((hpp - z) >> 63)
			F[i] = uint32(z) & 0x7FFFFFFF
			F[i+n] = uint32(z>>31) & 0x7FFFFFFF
		}
		for i := 0; i < n; i++ {
			// Apply CRT with two primes on the coefficient of G.
			x0 := G[i]   // mod p0
			x1 := G[i+n] // mod p1
			x0m1 := x0 - (p1 & ^tbmask(x0-p1))
			y := mp_mmul(mp_sub(x1, x0m1, p1), s, p1, p1_0i)
			z := uint64(x0) + uint64(p0)*uint64(y)
			z -= pp & -((hpp - z) >> 63)
			G[i] = uint32(z) & 0x7FFFFFFF
			G[i+n] = uint32(z>>31) & 0x7FFFFFFF
		}
	}
}

// Compute the squared norm of a small polynomial.
func poly_sqnorm(logn uint, f []int8) uint32 {
	n := 1 << logn
	s := uint32(0)
	for i := 0; i < n; i++ {
		x := int32(f[i])
		s += uint32(x * x)
	}
	return s
}
