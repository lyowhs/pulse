package fndsa

// Custom bignum implementation.
//
// Big integers are represented as sequences of 32-bit integers; the
// integer values are not necessarily consecutive in RAM (a dynamically
// provided "stride" value is added to the current word pointer, to get
// to the next word). The "len" parameter qualifies the number of words.
//
// Normal representation uses 31-bit limbs; each limb is stored in a
// 32-bit word, with the top bit (31) always cleared. Limbs are in
// low-to-high order. Signed integers use two's complement (hence, bit 30
// of the last limb is the sign bit).
//
// RNS representation of a big integer x is the sequence of values
// x modulo p, for the primes p defined in the primes[] array.

// Multiply the provided big integer m with a small value x. The big
// integer must have stride 1. This function assumes that x < 2^31
// and that the big integer uses unsigned notation. The carry word is
// returned.
func zint_mul_small(m []uint32, mlen int, x uint32) uint32 {
	cc := uint32(0)
	for i := 0; i < mlen; i++ {
		z := uint64(m[i])*uint64(x) + uint64(cc)
		m[i] = uint32(z) & 0x7FFFFFFF
		cc = uint32(z >> 31)
	}
	return cc
}

// Reduce a big integer d modulo a small integer p.
// Rules:
//
//	d is unsigned
//	p is prime
//	2^30 < p < 2^31
//	p0i = -1/p mod 2^32
//	r2 = 2^64 mod p
func zint_mod_small_unsigned(d []uint32, dlen int, stride int,
	p uint32, p0i uint32, r2 uint32) uint32 {

	// Algorithm: we inject words one by one, starting with the high
	// word. Each step is:
	//  - multiply x by 2^31
	//  - add new word
	if dlen == 0 {
		return 0
	}
	x := uint32(0)
	z := mp_half(r2, p)
	for i := (dlen - 1) * stride; i >= 0; i -= stride {
		w := d[i] - p
		w += p & tbmask(w)
		x = mp_mmul(x, z, p, p0i)
		x = mp_add(x, w, p)
	}
	return x
}

// Like zint_mod_small_unsigned() except that d uses signed convention.
// Extra parameter is rx = 2^(31*dlen) mod p.
func zint_mod_small_signed(d []uint32, dlen int, stride int,
	p uint32, p0i uint32, r2 uint32, rx uint32) uint32 {

	if dlen == 0 {
		return 0
	}
	z := zint_mod_small_unsigned(d, dlen, stride, p, p0i, r2)
	z = mp_sub(z, rx&-(d[(dlen-1)*stride]>>30), p)
	return z
}

// Add s*a to d. d and a initially have length len words; the new d
// has length len+1 words. Small integer s must fit on 31 bits. d and a
// must not overlap. d uses dstride, while a has stride 1.
func zint_add_mul_small(d []uint32, dlen int, dstride int,
	a []uint32, s uint32) {

	cc := uint32(0)
	j := 0
	for i := 0; i < dlen; i++ {
		dw := d[j]
		aw := a[i]
		z := uint64(aw)*uint64(s) + uint64(dw) + uint64(cc)
		d[j] = uint32(z) & 0x7FFFFFFF
		cc = uint32(z >> 31)
		j += dstride
	}
	d[j] = cc
}

// Normalize a modular integer aorund 0: if x > m/2, then x is replaced
// with x - m. Input x uses unsigned convention, output is signed. The
// two integers x and m have the same length (len words). x uses xstride,
// while m has stride 1.
func zint_norm_zero(x []uint32, xlen int, xstride int, m []uint32) {
	if xlen == 0 {
		return
	}

	// Compare x with m/2. We use the shifted version of m, and m
	// is odd, so we really compare with (m-1)/2; we want to perform
	// the subtraction if and only if x > (m-1)/2.
	r := uint32(0)
	bb := uint32(0)
	j := (xlen - 1) * xstride
	for i := xlen - 1; i >= 0; i-- {
		// Get the two words to compare in wx and wp (both over
		// 31 bits exactly).
		wx := x[j]
		j -= xstride
		wp := (m[i] >> 1) | (bb << 30)
		bb = m[i] & 1

		// We set cc to -1, 0 or 1, depending on whether wp is
		// lower than, equal to, or greater than wx.
		cc := wp - wx
		cc = ((-cc) >> 31) | -(cc >> 31)

		// If r != 0 then it is either 1 or -1, and we keep its
		// value. Otherwise, if r = 0, then we replace it with cc.
		r |= cc & ((r & 1) - 1)
	}

	// At this point, r = -1, 0 or 1, depending on whether (m-1)/2
	// is lower than, equal to, or greater than x. We thus want to
	// do the subtraction only if r = -1.
	cc := uint32(0)
	s := tbmask(r)
	j = 0
	for i := 0; i < xlen; i++ {
		xw := x[j]
		w := xw - m[i] - cc
		cc = w >> 31
		xw ^= ((w & 0x7FFFFFFF) ^ xw) & s
		x[j] = xw
		j += xstride
	}
}

// Rebuild integers from their RNS representation. There are num_sets
// sets of n integers; within each set, the n integers are interleaved,
// so that words of a given integer occur every n slots in RAM (i.e.
// each integer has stride n, and the integers of a set start on
// consecutive words). Each integer has length xlen words. The sets are
// consecutive in RAM.
//
// If normalized_signed is true then the output values are normalized
// in [-m/2,m/2] (with m being the product of all involved small prime
// moduli) and returned in signed conventions; otherwise, output values
// are in [0,m-1] and use unsigned convention.
//
// tmp[] must have room for xlen words.
func zint_rebuild_CRT(xx []uint32, xlen int, n int,
	num_sets int, normalize_signed bool, tmp []uint32) {

	uu := 0
	tmp[0] = primes[0].p
	for i := 1; i < xlen; i++ {
		// At the entry of each loop iteration:
		//  - the first i words of each array have been
		//    reassembled;
		//  - the first i words of tmp[] contains the
		// product of the prime moduli processed so far.
		//
		// We call 'q' the product of all previous primes.
		p := primes[i].p
		p0i := primes[i].p0i
		r2 := primes[i].r2
		s := primes[i].s
		uu += n
		kk := 0
		for k := 0; k < num_sets; k++ {
			for j := 0; j < n; j++ {
				// xp = the integer x modulo the prime p for this iteration
				// xq = (x mod q) mod p
				xp := xx[kk+j+uu]
				xq := zint_mod_small_unsigned(xx[kk+j:], i, n, p, p0i, r2)

				// New value is:
				//   (x mod q) + q*(s*(xp - xq) mod p)
				xr := mp_mmul(s, mp_sub(xp, xq, p), p, p0i)
				zint_add_mul_small(xx[kk+j:], i, n, tmp, xr)
			}
			kk += n * xlen
		}

		// Update product of primes in tmp[].
		tmp[i] = zint_mul_small(tmp, i, p)
	}

	// Normalize the reconstructed values around 0.
	if normalize_signed {
		kk := 0
		for k := 0; k < num_sets; k++ {
			for j := 0; j < n; j++ {
				zint_norm_zero(xx[kk+j:], xlen, n, tmp)
			}
			kk += n * xlen
		}
	}
}

// Negate a big integer conditionally: a is replaced with -a if and only
// if ctl = 0xFFFFFFFF. Control value ctl must be 0x00000000 or 0xFFFFFFFF.
// The integer has stride 1.
func zint_negate(a []uint32, alen int, ctl uint32) {
	// If ctl = 0xFFFFFFFF then we flip the bits of a by XORing with
	// 0x7FFFFFFF, and we add 1 to the value. If ctl = 0 then we XOR
	// with 0 and add 0, which leaves the value unchanged.
	cc := -ctl
	m := ctl >> 1
	for i := 0; i < alen; i++ {
		aw := a[i]
		aw = (aw ^ m) + cc
		a[i] = aw & 0x7FFFFFFF
		cc = aw >> 31
	}
}

// Replace a with (a*xa+b*xb)/(2^31) and b with (a*ya+b*yb)/(2^31).
// The low bits are dropped (the caller should compute the coefficients
// such that these dropped bits are all zeros). If either or both
// yields a negative value, then the value is negated.
//
// Returned value is:
//
//	0  both values were positive
//	1  new a had to be negated
//	2  new b had to be negated
//	3  both new a and new b had to be negated
//
// Coefficients xa, xb, ya and yb may use the full signed 32-bit range.
// Integers a and b use stride 1.
func zint_co_reduce(a []uint32, b []uint32, vlen int,
	xa int64, xb int64, ya int64, yb int64) uint32 {

	cca := int64(0)
	ccb := int64(0)
	for i := 0; i < vlen; i++ {
		wa := a[i]
		wb := b[i]
		za := uint64(wa)*uint64(xa) + uint64(wb)*uint64(xb) + uint64(cca)
		zb := uint64(wa)*uint64(ya) + uint64(wb)*uint64(yb) + uint64(ccb)
		if i > 0 {
			a[i-1] = uint32(za) & 0x7FFFFFFF
			b[i-1] = uint32(zb) & 0x7FFFFFFF
		}
		cca = int64(za) >> 31
		ccb = int64(zb) >> 31
	}
	a[vlen-1] = uint32(cca) & 0x7FFFFFFF
	b[vlen-1] = uint32(ccb) & 0x7FFFFFFF

	nega := uint32(cca >> 63)
	negb := uint32(ccb >> 63)
	zint_negate(a, vlen, nega)
	zint_negate(b, vlen, negb)
	return -nega | (-negb << 1)
}

// Finish modular reduction. Rules on input parameters:
//
//	if neg = 1, then -m <= a < 0
//	if neg = 0, then 0 <= a < 2*m
//
// If neg = 0, then the top word of a[] is allowed to use 32 bits.
//
// Modulus m must be odd. Integers a and m have the same length len,
// and both use stride 1.
func zint_finish_mod(a []uint32, m []uint32, vlen int, neg uint32) {
	// First pass: compare a (assumed nonnegative) with m. Note that
	// if the top word uses 32 bits, subtracting m must yield a
	// value less than 2^31 since a < 2*m.
	cc := uint32(0)
	for i := 0; i < vlen; i++ {
		cc = (a[i] - m[i] - cc) >> 31
	}

	// If neg = 1 then we must add m (regardless of cc)
	// If neg = 0 and cc = 0 then we must subtract m
	// If neg = 0 and cc = 1 then we must do nothing
	//
	// In the loop below, we conditionally subtract either m or -m
	// from a. Word xm is a word of m (if neg = 0) or -m (if neg = 1);
	// but if neg = 0 and cc = 1, then ym = 0 and it forces mw to 0.
	xm := -neg >> 1
	ym := -(neg | (1 - cc))
	cc = neg
	for i := 0; i < vlen; i++ {
		mw := (m[i] ^ xm) & ym
		aw := a[i] - mw - cc
		a[i] = aw & 0x7FFFFFFF
		cc = aw >> 31
	}
}

// Replace a with (a*xa+b*xb)/(2^31) mod m, and b with
// (a*ya+b*yb)/(2^31) mod m. Modulus m must be odd; m0i = -1/m[0] mod 2^31.
// Integers a, b and m all have length len and stride 1.
func zint_co_reduce_mod(a []uint32, b []uint32, m []uint32, vlen int,
	m0i uint32, xa int64, xb int64, ya int64, yb int64) {

	// These are actually four combined Montgomery multiplications.
	cca := int64(0)
	ccb := int64(0)
	fa := uint64(((a[0]*uint32(xa) + b[0]*uint32(xb)) * m0i) & 0x7FFFFFFF)
	fb := uint64(((a[0]*uint32(ya) + b[0]*uint32(yb)) * m0i) & 0x7FFFFFFF)
	for i := 0; i < vlen; i++ {
		wa := uint64(a[i])
		wb := uint64(b[i])
		wm := uint64(m[i])
		za := wa*uint64(xa) + wb*uint64(xb) + wm*fa + uint64(cca)
		zb := wa*uint64(ya) + wb*uint64(yb) + wm*fb + uint64(ccb)
		if i > 0 {
			a[i-1] = uint32(za) & 0x7FFFFFFF
			b[i-1] = uint32(zb) & 0x7FFFFFFF
		}
		cca = int64(za) >> 31
		ccb = int64(zb) >> 31
	}
	a[vlen-1] = uint32(cca)
	b[vlen-1] = uint32(ccb)

	// At this point:
	//   -m <= a < 2*m
	//   -m <= b < 2*m
	// (this is a case of Montgomery reduction)
	// The top words of 'a' and 'b' may have a 32-th bit set.
	// We want to add or subtract the modulus, as required.
	zint_finish_mod(a, m, vlen, uint32(uint64(cca)>>63))
	zint_finish_mod(b, m, vlen, uint32(uint64(ccb)>>63))
}

// Given an odd x, compute -1/x mod 2^31.
func mp_ninv31(x uint32) uint32 {
	y := 2 - x
	y *= 2 - x*y
	y *= 2 - x*y
	y *= 2 - x*y
	y *= 2 - x*y
	return (-y) & 0x7FFFFFFF
}

// Compute GCD(x,y). x and y must be both odd. If the GCD is not 1, then
// this function returns false (failure). If the GCD is 1, then the function
// returns true, and u and v are set to integers such that:
//
//	0 <= u <= y
//	0 <= v <= x
//	x*u - y*v = 1
//
// x and y are unmodified. Both input value must have the same encoded
// length (len), and have stride 1. u and v also have size len each.
// tmp must have room for 4*len words. The x, y, u, v and tmp must not
// overlap in any way (x and y may overlap, but this is useless).
func zint_bezout(u []uint32, v []uint32, x []uint32, y []uint32,
	xlen int, tmp []uint32) bool {

	if xlen == 0 {
		return false
	}

	// Algorithm is basically the optimized binary GCD as described in:
	//    https://eprint.iacr.org/2020/972
	// The paper shows that with registers of size 2*k bits, one can
	// do k-1 inner iterations and get a reduction by k-1 bits. In
	// fact, it also works with registers of 2*k-1 bits (though not
	// 2*k-2; the "upper half" of the approximation must have at
	// least one extra bit). Here, we want to perform 31 inner
	// iterations (since that maps well to Montgomery reduction with
	// our 31-bit words) so we must use 63-bit approximations.
	//
	// We also slightly expand the original algorithm by maintaining
	// four coefficients (u0, u1, v0 and v1) instead of the two
	// coefficients (u, v), because we want a full Bezout relation,
	// not just a modular inverse.
	//
	// We set up integers u0, v0, u1, v1, a and b. Throughout the
	// algorithm, they maintain the following invariants:
	//   a = x*u0 - y*v0
	//   b = x*u1 - y*v1
	//   0 <= a <= x
	//   0 <= b <= y
	//   0 <= u0 < y
	//   0 <= v0 < x
	//   0 <= u1 <= y
	//   0 <= v1 < x
	u0 := tmp[:xlen]
	v0 := tmp[xlen : 2*xlen]
	u1 := u
	v1 := v
	a := tmp[2*xlen : 3*xlen]
	b := tmp[3*xlen : 4*xlen]

	// We'll need the Montgomery reduction coefficients.
	x0i := mp_ninv31(x[0])
	y0i := mp_ninv31(y[0])

	// Initial values:
	//   a = x   u0 = 1   v0 = 0
	//   b = y   u1 = y   v1 = x - 1
	// Note that x is odd, so computing x-1 is easy.
	copy(a, x[:xlen])
	copy(b, y[:xlen])
	u0[0] = 1
	for i := 1; i < xlen; i++ {
		u0[i] = 0
	}
	for i := 0; i < xlen; i++ {
		v0[i] = 0
	}
	copy(u1, y[:xlen])
	copy(v1, x[:xlen])
	v1[0] -= 1

	// Each input operand may be as large as 31*len bits, and we
	// reduce the total length by at least 31 bits at each iteration.
	for num := 62*xlen + 31; num >= 31; num -= 31 {
		// Extract the top 32 bits of a and b: if j is such that:
		//   2^(j-1) <= max(a,b) < 2^j
		// then we want:
		//   xa = (2^31)*floor(a / 2^(j-32)) + (a mod 2^31)
		//   xb = (2^31)*floor(a / 2^(j-32)) + (b mod 2^31)
		// (if j < 63 then xa = a and xb = b).
		c0 := uint32(0xFFFFFFFF)
		c1 := uint32(0xFFFFFFFF)
		cp := uint32(0xFFFFFFFF)
		a0 := uint32(0)
		a1 := uint32(0)
		b0 := uint32(0)
		b1 := uint32(0)
		for j := xlen - 1; j >= 0; j-- {
			aw := a[j]
			bw := b[j]
			a1 ^= c1 & (a1 ^ aw)
			a0 ^= c0 & (a0 ^ aw)
			b1 ^= c1 & (b1 ^ bw)
			b0 ^= c0 & (b0 ^ bw)
			cp = c0
			c0 = c1
			c1 &= (((aw | bw) + 0x7FFFFFFF) >> 31) - 1
		}

		// Possible situations:
		//   cp = 0, c0 = 0, c1 = 0
		//     j >= 63, top words of a and b are in a0:a1 and b0:b1
		//     (a1 and b1 are highest, a1|b1 != 0)
		//
		//   cp = -1, c0 = 0, c1 = 0
		//     32 <= j <= 62, a0:a1 and b0:b1 contain a and b, exactly
		//
		//   cp = -1, c0 = -1, c1 = 0
		//     j <= 31, a0 and a1 both contain a, b0 and b1 contain b
		//
		// When j >= 63, we align the top words to ensure that we get
		// the full 32 bits.
		// Note: input to lzcnt32 is always non-zero.
		s := lzcnt32(a1 | b1 | ((cp & c0) >> 1))
		ha := (a1 << s) | (a0 >> (31 - s))
		hb := (b1 << s) | (b0 >> (31 - s))

		// If j <= 62, then we instead use the non-aligned bits.
		ha ^= (cp & (ha ^ a1))
		hb ^= (cp & (hb ^ b1))

		// If j <= 31, then all of the above was bad, and we simply
		// clear the upper bits.
		ha &= ^c0
		hb &= ^c0

		// Assemble the approximate values xa and xb (63 bits each).
		xa := (uint64(ha) << 31) | uint64(a[0])
		xb := (uint64(hb) << 31) | uint64(b[0])

		// Compute reduction factors:
		//   a' = a*pa + b*pb
		//   b' = a*qa + b*qb
		// such that a' and b' are both multiples of 2^31, but are
		// only marginally larger than a and b.
		// Each coefficient is in the -(2^31-1)..+2^31 range. To keep
		// them on 32-bit values, we compute pa+(2^31-1)... and so on.
		fg0 := uint64(1)
		fg1 := uint64(1) << 32
		for i := 0; i < 31; i++ {
			a_odd := -(xa & 1)
			dx := uint64(int64(xa-xb) >> 63)
			swap := a_odd & dx
			t1 := swap & (xa ^ xb)
			xa ^= t1
			xb ^= t1
			t2 := swap & (fg0 ^ fg1)
			fg0 ^= t2
			fg1 ^= t2
			xa -= a_odd & xb
			fg0 -= a_odd & fg1
			xa >>= 1
			fg1 <<= 1
		}

		// Split update factors.
		fg0 += uint64(0x7FFFFFFF7FFFFFFF)
		fg1 += uint64(0x7FFFFFFF7FFFFFFF)
		f0 := int64(fg0&0xFFFFFFFF) - 0x7FFFFFFF
		g0 := int64(fg0>>32) - 0x7FFFFFFF
		f1 := int64(fg1&0xFFFFFFFF) - 0x7FFFFFFF
		g1 := int64(fg1>>32) - 0x7FFFFFFF

		// Apply the update factors.
		negab := zint_co_reduce(a, b, xlen, f0, g0, f1, g1)
		f0 -= (f0 + f0) & -int64(negab&1)
		g0 -= (g0 + g0) & -int64(negab&1)
		f1 -= (f1 + f1) & -int64(negab>>1)
		g1 -= (g1 + g1) & -int64(negab>>1)
		zint_co_reduce_mod(u0, u1, y, xlen, y0i, f0, g0, f1, g1)
		zint_co_reduce_mod(v0, v1, x, xlen, x0i, f0, g0, f1, g1)
	}

	// b contains GCD(x,y), provided that x and y were indeed odd.
	// Result is correct if the GCD is 1.
	r := b[0] ^ 1
	for j := 1; j < xlen; j++ {
		r |= b[j]
	}
	r |= (x[0] & y[0] & 1) ^ 1
	return r == 0
}

// Add k*(2^sc)*y to x. The result is assumed to fit in the array of
// size xlen (truncation is applied if necessary). Scale factor sc
// is provided as sch and scl such that sc = 31*sch + scl and scl
// is in [0,30].
// xlen MUST NOT be lower than ylen; however, it is allowed that xlen is
// greater than ylen.
// x and y both use signed convention and have the same stride.
func zint_add_scaled_mul_small(x []uint32, xlen int,
	y []uint32, ylen int, stride int, k int32, sch uint32, scl uint32) {

	if ylen == 0 {
		return
	}

	ysign := -(y[stride*(ylen-1)] >> 30) >> 1
	tw := uint32(0)
	cc := int32(0)
	b := int(sch) * stride
	j := 0
	for i := int(sch); i < xlen; i++ {
		// Get the next word of (2^sc)*y.
		var wy uint32
		if ylen > 0 {
			wy = y[j]
			j += stride
			ylen--
		} else {
			wy = ysign
		}
		wys := ((wy << scl) & 0x7FFFFFFF) | tw
		tw = wy >> (31 - scl)

		// The expression below does not overflow.
		z := uint64(int64(wys)*int64(k) + int64(x[b]) + int64(cc))
		x[b] = uint32(z) & 0x7FFFFFFF
		b += stride

		// New carry word is a _signed_ right-shift of z.
		cc = int32(z >> 31)
	}
}

// Subtract y*2^sc from x. This is a specialized version of
// zint_add_scaled_mul_small(), with multiplier k = -1.
func zint_sub_scaled(x []uint32, xlen int,
	y []uint32, ylen int, stride int, sch uint32, scl uint32) {

	if ylen == 0 {
		return
	}

	ysign := -(y[stride*(ylen-1)] >> 30) >> 1
	tw := uint32(0)
	cc := uint32(0)
	b := int(sch) * stride
	j := 0
	for i := int(sch); i < xlen; i++ {
		// Get the next word of (2^sc)*y.
		var wy uint32
		if ylen > 0 {
			wy = y[j]
			j += stride
			ylen--
		} else {
			wy = ysign
		}
		wys := ((wy << scl) & 0x7FFFFFFF) | tw
		tw = wy >> (31 - scl)

		w := x[b] - wys - cc
		x[b] = w & 0x7FFFFFFF
		cc = w >> 31
		b += stride
	}
}
