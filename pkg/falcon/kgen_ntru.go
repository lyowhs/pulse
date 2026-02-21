package fndsa

// NTRU equation solving.
//
// Given small polynomials f and g, solving the NTRU equation means finding
// small polynomials F and G such that f*G - g*F = q (modulo X^n+1).
//
// The implementation requires that f and g have odd parity. It may find
// a solution only if the resultants of f and g, respectively, with X^n+1
// are prime to each other. Even when a solution mathematically exists, the
// implementation may fail to find it. In general, when a solution exists,
// there are several, which are not trivially derived from each other; it
// is unspecified which solution is returned (however, this code is
// deterministic and will always return the same solution for a given (f,g)
// input).

var max_bl_small = []uint16{
	1, 1, 2, 3, 4, 8, 14, 27, 53, 104, 207,
}
var max_bl_large = []uint16{
	1, 2, 3, 6, 11, 21, 40, 78, 155, 308,
}
var word_win = []uint16{
	1, 1, 2, 2, 2, 3, 3, 4, 5, 7,
}
var min_save_fg = []uint16{
	0, 0, 1, 2, 2, 2, 2, 2, 2, 3, 3,
}

func alloc(tmp []uint32, off int, sz int) ([]uint32, int) {
	return tmp[off : off+sz], off + sz
}

// Convert source f and g into RNS+NTT, at the start of the provided tmp[]
// (one word per coefficient).
func make_fg_zero(logn uint, f []int8, g []int8, tmp []uint32) {
	n := 1 << logn
	ft, off := alloc(tmp, 0, n)
	gt, off := alloc(tmp, off, n)
	gm := tmp[off:]
	p := primes[0].p
	p0i := primes[0].p0i
	poly_mp_set_small(logn, ft, f, p)
	poly_mp_set_small(logn, gt, g, p)
	mp_mkgm(logn, gm, primes[0].g, p, p0i)
	mp_NTT(logn, ft, gm, p, p0i)
	mp_NTT(logn, gt, gm, p, p0i)
}

// One step of computing (f,g) at a given depth.
//
//	Input: (f,g) of degree 2^(logn_top-depth)
//	Output: (f',g') of degree 2^(logn_top-(depth+1))
//
// Input and output values are at the start of tmp[], in RNS+NTT notation.
//
// RAM USAGE: 3*(2^logn_top) (at most)
// (assumptions: max_bl_small[0] = max_bl_small[1] = 1, max_bl_small[2] = 2) */
func make_fg_step(logn_top uint, depth uint, tmp []uint32) {
	logn := logn_top - depth
	n := 1 << logn
	hn := n >> 1
	slen := int(max_bl_small[depth])
	tlen := int(max_bl_small[depth+1])

	// Layout:
	//   fd    output f' (hn*tlen)
	//   gd    output g' (hn*tlen)
	//   fs    source (n*slen)
	//   gs    source (n*slen)
	//   t1    NTT support (n)
	//   t2    extra (max(n, slen - n))
	fd, off := alloc(tmp, 0, hn*tlen)
	gd, off := alloc(tmp, off, hn*tlen)
	fgs, off := alloc(tmp, off, 2*n*slen)
	fs := fgs[:n*slen]
	gs := fgs[n*slen:]
	off_t1 := off
	t1, off := alloc(tmp, off, n)
	t2 := tmp[off:]
	copy(fgs, tmp)

	// First slen words: we use the input values directly, and apply
	// inverse NTT as we go, so that we get the sources in RNS (non-NTT).
	for i := 0; i < slen; i++ {
		p := primes[i].p
		p0i := primes[i].p0i
		r2 := primes[i].r2
		ks := i * n
		kd := i * hn
		for j := 0; j < hn; j++ {
			fd[kd+j] = mp_mmul(
				mp_mmul(fs[ks+2*j], fs[ks+2*j+1], p, p0i),
				r2, p, p0i)
			gd[kd+j] = mp_mmul(
				mp_mmul(gs[ks+2*j], gs[ks+2*j+1], p, p0i),
				r2, p, p0i)
		}
		mp_mkigm(logn, t1, primes[i].ig, p, p0i)
		mp_iNTT(logn, fs[ks:], t1, p, p0i)
		mp_iNTT(logn, gs[ks:], t1, p, p0i)
	}

	// Now that fs and gs are in RNS, rebuild their plain integer
	// coefficients.
	zint_rebuild_CRT(fgs, slen, n, 2, true, tmp[off_t1:])

	// Remaining output words.
	for i := slen; i < tlen; i++ {
		p := primes[i].p
		p0i := primes[i].p0i
		r2 := primes[i].r2
		rx := mp_Rx31(slen, p, p0i, r2)
		mp_mkgm(logn, t1, primes[i].g, p, p0i)
		kd := i * hn

		for j := 0; j < n; j++ {
			t2[j] = zint_mod_small_signed(fs[j:], slen, n, p, p0i, r2, rx)
		}
		mp_NTT(logn, t2, t1, p, p0i)
		for j := 0; j < hn; j++ {
			fd[kd+j] = mp_mmul(
				mp_mmul(t2[2*j], t2[2*j+1], p, p0i), r2, p, p0i)
		}

		for j := 0; j < n; j++ {
			t2[j] = zint_mod_small_signed(gs[j:], slen, n, p, p0i, r2, rx)
		}
		mp_NTT(logn, t2, t1, p, p0i)
		for j := 0; j < hn; j++ {
			gd[kd+j] = mp_mmul(
				mp_mmul(t2[2*j], t2[2*j+1], p, p0i), r2, p, p0i)
		}
	}
}

// Compute (f,g) at a specified depth, in RNS+NTT notation.
// Computed values are stored at the start of the provided tmp[] (slen
// words per coefficient).
//
// This function is for depth < logn_top. For the deepest layer, use
// make_fg_deepest().
//
// RAM USAGE: 3*(2^logn_top)
func make_fg_intermediate(logn_top uint,
	f []int8, g []int8, depth uint, tmp []uint32) {

	make_fg_zero(logn_top, f, g, tmp)
	for d := uint(0); d < depth; d++ {
		make_fg_step(logn_top, d, tmp)
	}
}

// Compute (f,g) at the deepest level (i.e. get Res(f,X^n+1) and
// Res(g,X^n+1)). Intermediate (f,g) values (below the save threshold)
// are copied at the end of tmp (of size save_off words).
//
// If f is not invertible modulo X^n+1 and modulo p = 2147473409, then
// this function returns false and nothing else is computed. Otherwise it
// returns true.
func make_fg_deepest(logn_top uint,
	f []int8, g []int8, tmp []uint32, sav_off int) bool {

	make_fg_zero(logn_top, f, g, tmp)

	// f is now in RNS+NTT, so we can test its invertibility (mod p)
	// by simply checking that all NTT coefficients are non-zero.
	// (This invertibility allows recovering of G from f, g and F
	// by working modulo p = 2147473409. It is not actually necessary
	// since the recovery of G is normally done modulo q = 12289, but
	// it was done in the original ntrugen code, so it is maintained
	// here for full compatibility of test vectors.)
	n := 1 << logn_top
	b := uint32(0)
	for i := 0; i < n; i++ {
		b |= tmp[i] - 1
	}
	if (b >> 31) != 0 {
		return false
	}

	for d := uint(0); d < logn_top; d++ {
		make_fg_step(logn_top, d, tmp)

		// make_fg_step() computes the (f,g) for depth d+1; we
		// save that value if d+1 is at least at the save
		// threshold, but is not the deepest level.
		d2 := d + 1
		if d2 < logn_top && d2 >= uint(min_save_fg[logn_top]) {
			slen := int(max_bl_small[d2])
			fglen := slen << (logn_top + 1 - d2)
			sav_off -= fglen
			copy(tmp[sav_off:], tmp[:fglen])
		}
	}
	return true
}

// Solve the NTRU equation at the deepest level. This computes the
// integers F and G such that Res(f,X^n+1)*G - Res(g,X^n+1)*F = q.
// The two integers are written into tmp[].
//
// Returned value: true on success, false on error.
//
// RAM USAGE: max(3*(2^logn_top), 8*max_bl_small[depth])
func solve_NTRU_deepest(logn_top uint, f []int8, g []int8, tmp []uint32) bool {
	// Get (f,g) at the deepest level (i.e. Res(f,X^n+1) and Res(g,X^n+1)).
	// Obtained (f,g) are in RNS+NTT (since degree n = 1, this is
	// equivalent to RNS).
	if !make_fg_deepest(logn_top, f, g, tmp, 6<<logn_top) {
		return false
	}

	// Reorganize memory:
	//    Fp   output F (slen)
	//    Gp   output G (slen)
	//    fp   Res(f,X^n+1) (slen)
	//    gp   Res(g,X^n+1) (slen)
	//    t1   rest of temporary
	slen := int(max_bl_small[logn_top])
	Fp, off := alloc(tmp, 0, slen)
	Gp, off := alloc(tmp, off, slen)
	fgp, off := alloc(tmp, off, 2*slen)
	fp := fgp[:slen]
	gp := fgp[slen:]
	t1 := tmp[off:]
	copy(fgp, tmp)

	// Convert back the resultants into plain integers.
	zint_rebuild_CRT(fgp, slen, 1, 2, false, t1)

	// Apply the binary GCD to get a solution (F,G) such that:
	//   f*G - g*F = 1
	if !zint_bezout(Gp, Fp, fp, gp, slen, t1) {
		return false
	}

	// Multiply the obtained (F,G) by q to get a proper solution:
	//   f*G - g*F = q
	if zint_mul_small(Fp, slen, q) != 0 || zint_mul_small(Gp, slen, q) != 0 {
		return false
	}
	return true
}

// We use poly_sub_scaled() when log(n) < min_logn_fgntt, and
// poly_sub_scaled_ntt() when log(n) >= min_logn_fgntt. The NTT variant
// is faster at large degrees, but not at small degrees.
const min_logn_fgntt = uint(4)

// Solving the NTRU equation, intermediate level.
// Input is (F,G) from one level deeper (half-degree), in plain
// representation, at the start of tmp[]; output is (F,G) from this
// level, written at the start of tmp[].
//
// Returned value: true on success, false on error.
func solve_NTRU_intermediate(logn_top uint,
	f []int8, g []int8, depth uint, tmp []uint32, tmp_fxr []fxr) bool {

	logn := logn_top - depth
	n := 1 << logn
	hn := n >> 1

	// slen   size for (f,g) at this level (also output (F,G))
	// llen   size for unreduced (F,G) at this level
	// dlen   size for input (F,G) from deeper level
	// Note: we always have llen >= dlen
	slen := int(max_bl_small[depth])
	llen := int(max_bl_large[depth])
	dlen := int(max_bl_small[depth+1])

	// Fd   F from deeper level (dlen*hn)
	// Gd   G from deeper level (dlen*hn)
	// ft   f from this level (slen*n)
	// gt   g from this level (slen*n)
	Fd, off := alloc(tmp, 0, dlen*hn)
	Gd, off := alloc(tmp, off, dlen*hn)
	fgt := tmp[off:]

	// Get (f,g) for this level (in RNS+NTT).
	if depth < uint(min_save_fg[logn_top]) {
		make_fg_intermediate(logn_top, f, g, depth, fgt)
	} else {
		sav_off := 6 << logn_top
		for d := uint(min_save_fg[logn_top]); d <= depth; d++ {
			sav_off -= int(max_bl_small[d]) << (logn_top + 1 - d)
		}
		copy(fgt[:2*slen*n], tmp[sav_off:])
	}

	// Move buffers so that we have room for the unreduced (F,G) at
	// this level.
	//   Ft   F from this level (unreduced) (llen*n)
	//   Gt   G from this level (unreduced) (llen*n)
	//   ft   f from this level (slen*n)
	//   gt   g from this level (slen*n)
	//   Fd   F from deeper level (dlen*hn)
	//   Gd   G from deeper level (dlen*hn)
	FGt, off := alloc(tmp, 0, 2*n*llen)
	Ft := FGt[:llen*n]
	Gt := FGt[llen*n:]
	copy(tmp[off:], fgt[:2*n*slen])
	off_ft := off
	off_gt := off + n*slen
	fgt, off = alloc(tmp, off, 2*n*slen)
	ft := fgt[:n*slen]
	gt := fgt[n*slen:]
	off_FGd := off
	Fd, off = alloc(tmp, off, dlen*hn)
	Gd, off = alloc(tmp, off, dlen*hn)
	t1 := tmp[off:]
	copy(tmp[off_FGd:], tmp[:2*hn*dlen])

	// Convert Fd and Gd to RNS, with output temporarily stored
	// in (Ft, Gt). Fd and Gd have degree hn only; we store the
	// values for each modulus p in the _last_ hn slots of the
	// n-word line for that modulus.
	for i := 0; i < llen; i++ {
		p := primes[i].p
		p0i := primes[i].p0i
		r2 := primes[i].r2
		rx := mp_Rx31(dlen, p, p0i, r2)
		kt := i*n + hn
		for j := 0; j < hn; j++ {
			Ft[kt+j] = zint_mod_small_signed(Fd[j:], dlen, hn, p, p0i, r2, rx)
			Gt[kt+j] = zint_mod_small_signed(Gd[j:], dlen, hn, p, p0i, r2, rx)
		}
	}

	// Fd and Gd are no longer needed.
	t1 = tmp[off_FGd:]
	off_t1 := off_FGd

	// Compute (F,G) (unreduced) modulo sufficiently many small primes.
	// We also un-NTT (f,g) as we go; when slen primes have been
	// processed, we obtain (f,g) in RNS, and we apply the CRT to
	// get (f,g) in plain representation.
	for i := 0; i < llen; i++ {
		// If we have processed exactly slen primes, then (f,g)
		// are in RNS, and we can rebuild them.
		if i == slen {
			zint_rebuild_CRT(fgt, slen, n, 2, true, t1)
		}

		p := primes[i].p
		p0i := primes[i].p0i
		r2 := primes[i].r2

		// Memory layout: we keep Ft, Gt, ft and gt; we append:
		//   gm    NTT support (n)
		//   igm   iNTT support (n)
		//   fx    temporary f mod p (NTT) (n)
		//   gx    temporary g mod p (NTT) (n)
		gm, off := alloc(t1, 0, n)
		igm, off := alloc(t1, off, n)
		fx, off := alloc(t1, off, n)
		gx := t1[off:]
		mp_mkgmigm(logn, gm, igm, primes[i].g, primes[i].ig, p, p0i)
		if i < slen {
			copy(fx, ft[i*n:])
			copy(gx, gt[i*n:])
			mp_iNTT(logn, ft[i*n:], igm, p, p0i)
			mp_iNTT(logn, gt[i*n:], igm, p, p0i)
		} else {
			rx := mp_Rx31(slen, p, p0i, r2)
			for j := 0; j < n; j++ {
				fx[j] = zint_mod_small_signed(ft[j:], slen, n, p, p0i, r2, rx)
				gx[j] = zint_mod_small_signed(gt[j:], slen, n, p, p0i, r2, rx)
			}
			mp_NTT(logn, fx, gm, p, p0i)
			mp_NTT(logn, gx, gm, p, p0i)
		}

		// We have (F,G) from deeper level in Ft and Gt, in
		// RNS. We apply the NTT modulo p.
		Fe := Ft[i*n:]
		Ge := Gt[i*n:]
		mp_NTT(logn-1, Fe[hn:], gm, p, p0i)
		mp_NTT(logn-1, Ge[hn:], gm, p, p0i)

		// Compute F and G (unreduced) modulo p.
		for j := 0; j < hn; j++ {
			fa := fx[(j<<1)+0]
			fb := fx[(j<<1)+1]
			ga := gx[(j<<1)+0]
			gb := gx[(j<<1)+1]
			mFp := mp_mmul(Fe[j+hn], r2, p, p0i)
			mGp := mp_mmul(Ge[j+hn], r2, p, p0i)
			Fe[(j<<1)+0] = mp_mmul(gb, mFp, p, p0i)
			Fe[(j<<1)+1] = mp_mmul(ga, mFp, p, p0i)
			Ge[(j<<1)+0] = mp_mmul(fb, mGp, p, p0i)
			Ge[(j<<1)+1] = mp_mmul(fa, mGp, p, p0i)
		}

		// We want the new (F,G) in RNS only (no NTT).
		mp_iNTT(logn, Fe, igm, p, p0i)
		mp_iNTT(logn, Ge, igm, p, p0i)
	}

	// Edge case: if slen == llen, then we have not rebuilt (f,g)
	// into plain representation yet, so we do it now.
	if slen == llen {
		zint_rebuild_CRT(fgt, slen, n, 2, true, t1)
	}

	// We now have the unreduced (F,G) in RNS. We rebuild their
	// plain representation.
	zint_rebuild_CRT(FGt, llen, n, 2, true, t1)

	// We now reduce these (F,G) with Babai's nearest plane
	// algorithm. The reduction conceptually goes as follows:
	//   k <- round((F*adj(f) + G*adj(g))/(f*adj(f) + g*adj(g)))
	//   (F, G) <- (F - k*f, G - k*g)
	// We use fixed-point approximations of (f,g) and (F, G) to get
	// a value k as a small polynomial with scaling; we then apply
	// k on the full-width polynomial. Each iteration "shaves" a
	// a few bits off F and G.
	//
	// We apply the process sufficiently many times to reduce (F, G)
	// to the size of (f, g) with a reasonable probability of success.
	// Since we want full constant-time processing, the number of
	// iterations and the accessed slots work on some assumptions on
	// the sizes of values (sizes have been measured over many samples,
	// and a margin of 5 times the standard deviation).

	// If depth is at least 2, and we will use the NTT to subtract
	// k*(f,g) from (F,G), then we will need to convert (f,g) to NTT over
	// slen+1 words, which requires an extra word to ft and gt.
	use_sub_ntt := depth > uint(1) && logn >= min_logn_fgntt
	slen_adj := slen
	if use_sub_ntt {
		slen_adj = slen + 1
		copy(tmp[off_gt+n:], gt)
		off_gt += n
		ft = tmp[off_ft : off_ft+n*slen_adj]
		gt = tmp[off_gt : off_gt+n*slen_adj]
		off_t1 += 2 * n
		t1 = tmp[off_t1:]
	}

	// New layout:
	//   Ft    F from this level (unreduced) (llen*n)
	//   Gt    G from this level (unreduced) (llen*n)
	//   ft    f from this level (slen*n) (+n if use_sub_ntt)
	//   gt    g from this level (slen*n) (+n if use_sub_ntt)
	// In tmp_fxr:
	//   rt3   (n)
	//   rt4   (n)
	//   rt1   (hn)
	rt3 := tmp_fxr[:n]
	rt4 := tmp_fxr[n : 2*n]
	rt1 := tmp_fxr[2*n:]

	// We consider only the top rlen words of (f,g).
	rlen := int(word_win[depth])
	if rlen > slen {
		rlen = slen
	}
	blen := slen - rlen
	scale_fg := uint32(blen) * 31
	scale_FG := uint32(llen) * 31

	// Convert f and g into fixed-point approximations, in rt3 and rt4,
	// respectively. They are scaled down by 2^(scale_fg + scale_x).
	// scale_fg is public (it depends only on the recursion depth), but
	// scale_x comes from a measurement on the actual values of (f,g) and
	// is thus secret.
	//
	// The value scale_x is adjusted so that the largest coefficient is
	// close to, but lower than, some limit t (in absolute value). The
	// limit t is chosen so that f*adj(f) + g*adj(g) does not overflow,
	// i.e. all coefficients must remain below 2^31.
	//
	// Let n be the degree; we know that n <= 2^10. The squared norm
	// of a polynomial is the sum of the squared norms of the
	// coefficients, with the squared norm of a complex number being
	// the product of that number with its complex conjugate. If all
	// coefficients of f are less than t (in absolute value), then
	// the squared norm of f is less than n*t^2. The squared norm of
	// FFT(f) (f in FFT representation) is exactly n times the
	// squared norm of f, so this leads to n^2*t^2 as a maximum
	// bound. adj(f) has the same norm as f. This implies that each
	// complex coefficient of FFT(f) has a maximum squared norm of
	// n^2*t^2 (with a maximally imbalanced polynomial with all
	// coefficient but one being zero). The computation of f*adj(f)
	// exactly is, in FFT representation, the product of each
	// coefficient with its conjugate; thus, the coefficients of
	// f*adj(f), in FFT representation, are at most n^2*t^2.
	//
	// Since we want the coefficients of f*adj(f)+g*adj(g) not to exceed
	// 2^31, we need n^2*t^2 <= 2^30, i.e. n*t <= 2^15. We can adjust t
	// accordingly (called scale_t in the code below). We also need to
	// take care that t must not exceed scale_x. Approximation of f and
	// g are extracted with scale scale_fg + scale_x - scale_t, and
	// later fixed by dividing them by 2^scale_t.
	scale_xf := poly_max_bitlength(logn, ft[blen*n:], rlen)
	scale_xg := poly_max_bitlength(logn, gt[blen*n:], rlen)
	scale_x := scale_xf
	scale_x ^= (scale_xf ^ scale_xg) & tbmask(scale_xf-scale_xg)
	scale_t := uint32(15 - logn)
	scale_t ^= (scale_t ^ scale_x) & tbmask(scale_x-scale_t)
	scdiff := scale_x - scale_t

	poly_big_to_fixed(logn, rt3, ft[blen*n:], rlen, scdiff)
	poly_big_to_fixed(logn, rt4, gt[blen*n:], rlen, scdiff)

	// rt3 <- adj(f)/(f*adj(f) + g*adj(g))  (FFT)
	// rt4 <- adj(g)/(f*adj(f) + g*adj(g))  (FFT)
	vect_FFT(logn, rt3)
	vect_FFT(logn, rt4)
	vect_norm_fft(logn, rt1, rt3, rt4)
	vect_mul2e(logn, rt3, scale_t)
	vect_mul2e(logn, rt4, scale_t)
	for i := 0; i < hn; i++ {
		rt3[i] = fxr_div(rt3[i], rt1[i])
		rt3[i+hn] = fxr_div(fxr_neg(rt3[i+hn]), rt1[i])
		rt4[i] = fxr_div(rt4[i], rt1[i])
		rt4[i+hn] = fxr_div(fxr_neg(rt4[i+hn]), rt1[i])
	}

	// New layout:
	//   Ft    F from this level (unreduced) (llen*n)
	//   Gt    G from this level (unreduced) (llen*n)
	//   ft    f from this level (slen*n) (+n if use_sub_ntt)
	//   gt    g from this level (slen*n) (+n if use_sub_ntt)
	//   k     n
	//   t2    3*n
	// In tmp_fxr:
	//   rt3   (n)
	//   rt4   (n)
	//   rt1   (n)
	//   rt2   (n)
	//
	// In the C implementation, tmp_fxr shares the same space as
	// tmp: rt3 starts right after gt; k and t2 share the same area
	// as rt1 and rt2. Moreover, ft and gt are removed at depth 1.
	// Since here the spaces are separate, we do not need this area
	// sharing.
	k, off := alloc(t1, 0, n)
	t2 := t1[off:]
	rt1 = tmp_fxr[2*n : 3*n]
	rt2 := tmp_fxr[3*n:]

	// If we are going to use poly_sub_scaled_ntt(), then we convert
	// f and g to the NTT representation. Since poly_sub_scaled_ntt()
	// itself will use more than n*(slen+2) words in t2[], we can do
	// the same here.
	if use_sub_ntt {
		gm := t2[:n]
		tn := t2[n:]
		for i := 0; i < slen_adj; i++ {
			p := primes[i].p
			p0i := primes[i].p0i
			r2 := primes[i].r2
			rx := mp_Rx31(slen, p, p0i, r2)
			mp_mkgm(logn, gm, primes[i].g, p, p0i)
			for j := 0; j < n; j++ {
				tn[(i<<logn)+j] = zint_mod_small_signed(
					ft[j:], slen, n, p, p0i, r2, rx)
			}
			mp_NTT(logn, tn[(i<<logn):], gm, p, p0i)
		}
		copy(ft, tn[:slen_adj*n])
		for i := 0; i < slen_adj; i++ {
			p := primes[i].p
			p0i := primes[i].p0i
			r2 := primes[i].r2
			rx := mp_Rx31(slen, p, p0i, r2)
			mp_mkgm(logn, gm, primes[i].g, p, p0i)
			for j := 0; j < n; j++ {
				tn[(i<<logn)+j] = zint_mod_small_signed(
					gt[j:], slen, n, p, p0i, r2, rx)
			}
			mp_NTT(logn, tn[(i<<logn):], gm, p, p0i)
		}
		copy(gt, tn[:slen_adj*n])
	}

	// Reduce F and G repeatedly.
	FGlen := llen
	var reduce_bits uint32
	switch logn_top {
	case 9:
		reduce_bits = 13
	case 10:
		reduce_bits = 11
	default:
		reduce_bits = 16
	}
	for {
		// Convert the current F and G into fixed-point. We want
		// to apply scaling scale_FG + scale_x.
		sch, toff := divrem31(scale_FG)
		tlen := int(sch)
		poly_big_to_fixed(logn, rt1,
			Ft[tlen*n:], FGlen-tlen, scale_x+toff)
		poly_big_to_fixed(logn, rt2,
			Gt[tlen*n:], FGlen-tlen, scale_x+toff)

		// rt2 <- (F*adj(f) + G*adj(g)) / (f*adj(f) + g*adj(g))
		vect_FFT(logn, rt1)
		vect_FFT(logn, rt2)
		vect_mul_fft(logn, rt1, rt3)
		vect_mul_fft(logn, rt2, rt4)
		vect_add(logn, rt2, rt1)
		vect_iFFT(logn, rt2)

		// k <- round(rt2)
		for i := 0; i < n; i++ {
			k[i] = uint32(fxr_round(rt2[i]))
		}

		// (f,g) are scaled by scale_fg + scale_x
		// (F,G) are scaled by scale_FG + scale_x
		// Thus, k is scaled by scale_FG - scale_fg, which is public.
		scale_k := scale_FG - scale_fg
		if depth == 1 {
			poly_sub_kfg_scaled_depth1(logn_top, Ft, Gt, FGlen,
				k, scale_k, f, g, t2)
		} else if use_sub_ntt {
			poly_sub_scaled_ntt(logn, Ft, FGlen, ft, slen,
				k, scale_k, t2)
			poly_sub_scaled_ntt(logn, Gt, FGlen, gt, slen,
				k, scale_k, t2)
		} else {
			poly_sub_scaled(logn, Ft, FGlen, ft, slen, k, scale_k)
			poly_sub_scaled(logn, Gt, FGlen, gt, slen, k, scale_k)
		}

		// We now assume that F and G have shrunk by at least
		// reduce_bits. We adjust FGlen accordinly.
		if scale_FG <= scale_fg {
			break
		}
		if scale_FG <= (scale_fg + reduce_bits) {
			scale_FG = scale_fg
		} else {
			scale_FG -= reduce_bits
		}
		for FGlen > slen &&
			31*(FGlen-slen) > int(scale_FG-scale_fg+30) {
			FGlen--
		}
	}

	// Output F is already in the right place; G is in Gt, and must be
	// moved back a bit.
	copy(tmp[slen*n:], Gt[:slen*n])
	Ft = tmp[:slen*n]
	Gt = tmp[slen*n : 2*slen*n]

	// Reduction is done. We test the current solution modulo a single
	// prime.
	// Exception: we cannot do that if depth == 1, since in that case
	// we did not keep (ft,gt). Reduction errors rarely occur at this
	// stage, so we can omit that test (depth-0 test will cover it).
	//
	// If use_sub_ntt != 0, then ft and gt are already in NTT
	// representation.
	if depth == 1 {
		return true
	}

	t2, off = alloc(t1, n, n)
	t3, off := alloc(t1, off, n)
	t4 := t1[off:]
	p := primes[0].p
	p0i := primes[0].p0i
	r2 := primes[0].r2
	rx := mp_Rx31(slen, p, p0i, r2)
	mp_mkgm(logn, t4, primes[0].g, p, p0i)
	if use_sub_ntt {
		t1 = ft
		for i := 0; i < n; i++ {
			t2[i] = zint_mod_small_signed(Gt[i:], slen, n, p, p0i, r2, rx)
		}
		mp_NTT(logn, t2, t4, p, p0i)
	} else {
		for i := 0; i < n; i++ {
			t1[i] = zint_mod_small_signed(ft[i:], slen, n, p, p0i, r2, rx)
			t2[i] = zint_mod_small_signed(Gt[i:], slen, n, p, p0i, r2, rx)
		}
		mp_NTT(logn, t1, t4, p, p0i)
		mp_NTT(logn, t2, t4, p, p0i)
	}
	for i := 0; i < n; i++ {
		t3[i] = mp_mmul(t1[i], t2[i], p, p0i)
	}
	if use_sub_ntt {
		t1 = gt
		for i := 0; i < n; i++ {
			t2[i] = zint_mod_small_signed(Ft[i:], slen, n, p, p0i, r2, rx)
		}
		mp_NTT(logn, t2, t4, p, p0i)
	} else {
		for i := 0; i < n; i++ {
			t1[i] = zint_mod_small_signed(gt[i:], slen, n, p, p0i, r2, rx)
			t2[i] = zint_mod_small_signed(Ft[i:], slen, n, p, p0i, r2, rx)
		}
		mp_NTT(logn, t1, t4, p, p0i)
		mp_NTT(logn, t2, t4, p, p0i)
	}
	rv := mp_mmul(q, 1, p, p0i)
	for i := 0; i < n; i++ {
		x := mp_mmul(t1[i], t2[i], p, p0i)
		if mp_sub(t3[i], x, p) != rv {
			return false
		}
	}

	return true
}

// Solving the NTRU equation, top recursion level. This is a specialized
// variant for solve_NTRU_intermediate() with depth == 0, for lower RAM
// usage and faster operation.
//
// Returned value: true on success, false on error.
func solve_NTRU_depth0(logn uint,
	f []int8, g []int8, tmp []uint32, tmp_fxr []fxr) bool {

	n := 1 << logn
	hn := n >> 1

	// At depth 0, all values fit on 30 bits, so we work with a
	// single modulus p.
	p := primes[0].p
	p0i := primes[0].p0i
	r2 := primes[0].r2

	// Buffer layout:
	//   Fd   F from upper level (hn)
	//   Gd   G from upper level (hn)
	//   ft   f (n)
	//   gt   g (n)
	//   gm   helper for NTT
	Fd, off := alloc(tmp, 0, hn)
	Gd, off := alloc(tmp, off, hn)
	ft, off := alloc(tmp, off, n)
	gt, off := alloc(tmp, off, n)
	gm := tmp[off:]

	// Load f and g, and convert to RNS+NTT.
	mp_mkgm(logn, gm, primes[0].g, p, p0i)
	poly_mp_set_small(logn, ft, f, p)
	poly_mp_set_small(logn, gt, g, p)
	mp_NTT(logn, ft, gm, p, p0i)
	mp_NTT(logn, gt, gm, p, p0i)

	// Convert Fd and Gd to RNS+NTT.
	poly_mp_set(logn-1, Fd, p)
	poly_mp_set(logn-1, Gd, p)
	mp_NTT(logn-1, Fd, gm, p, p0i)
	mp_NTT(logn-1, Gd, gm, p, p0i)

	// Build the unreduced (F,G) into ft and gt.
	for i := 0; i < hn; i++ {
		fa := ft[(i<<1)+0]
		fb := ft[(i<<1)+1]
		ga := gt[(i<<1)+0]
		gb := gt[(i<<1)+1]
		mFd := mp_mmul(Fd[i], r2, p, p0i)
		mGd := mp_mmul(Gd[i], r2, p, p0i)
		ft[(i<<1)+0] = mp_mmul(gb, mFd, p, p0i)
		ft[(i<<1)+1] = mp_mmul(ga, mFd, p, p0i)
		gt[(i<<1)+0] = mp_mmul(fb, mGd, p, p0i)
		gt[(i<<1)+1] = mp_mmul(fa, mGd, p, p0i)
	}

	// Reorganize buffers:
	//   Fp   unreduced F (RNS+NTT) (n)
	//   Gp   unreduced G (RNS+NTT) (n)
	//   t1   free (n)
	//   t2   NTT support (gm) (n)
	//   t3   free (n)
	//   t4   free (n)
	Fp, off := alloc(tmp, 0, n)
	Gp, off := alloc(tmp, off, n)
	t1, off := alloc(tmp, off, n)
	t2, off := alloc(tmp, off, n)
	t3, off := alloc(tmp, off, n)
	t4 := tmp[off:]
	copy(tmp[:2*n], tmp[n:])

	// Working modulo p (using the NTT), we compute:
	//    t1 <- F*adj(f) + G*adj(g)
	//    t2 <- f*adj(f) + g*adj(g)

	// t4 <- f (RNS+NTT)
	poly_mp_set_small(logn, t4, f, p)
	mp_NTT(logn, t4, gm, p, p0i)

	// t1 <- F*adj(f) (RNS+NTT)
	// t3 <- f*adj(f) (RNS+NTT)
	for i := 0; i < n; i++ {
		w := mp_mmul(t4[(n-1)-i], r2, p, p0i)
		t1[i] = mp_mmul(w, Fp[i], p, p0i)
		t3[i] = mp_mmul(w, t4[i], p, p0i)
	}

	// t4 <- g (RNS+NTT)
	poly_mp_set_small(logn, t4, g, p)
	mp_NTT(logn, t4, gm, p, p0i)

	// t1 <- t1 + G*adj(g)
	// t3 <- t3 + g*adj(g)
	for i := 0; i < n; i++ {
		w := mp_mmul(t4[(n-1)-i], r2, p, p0i)
		t1[i] = mp_add(t1[i], mp_mmul(w, Gp[i], p, p0i), p)
		t3[i] = mp_add(t3[i], mp_mmul(w, t4[i], p, p0i), p)
	}

	// Convert back F*adj(f) + G*adj(g) and f*adj(f) + g*adj(g) to
	// plain representation, and move f*adj(f) + g*adj(g) to t2.
	mp_mkigm(logn, t4, primes[0].ig, p, p0i)
	mp_iNTT(logn, t1, t4, p, p0i)
	mp_iNTT(logn, t3, t4, p, p0i)
	for i := 0; i < n; i++ {
		/* NOTE: no truncature to 31 bits. */
		t1[i] = uint32(mp_norm(t1[i], p))
		t2[i] = uint32(mp_norm(t3[i], p))
	}

	// Buffer contents:
	//   Fp   unreduced F (RNS+NTT) (n)
	//   Gp   unreduced G (RNS+NTT) (n)
	//   t1   F*adj(f) + G*adj(g) (plain, 32-bit) (n)
	//   t2   f*adj(f) + g*adj(g) (plain, 32-bit) (n)

	// We need to divide t1 by t2, and round the result. We convert
	// them to FFT representation, downscaled by 2^10 (to avoid overflows).
	// We first convert f*adj(f) + g*adj(g), which is self-adjoint;
	// thus, its FFT representation only has half-size.
	rt3 := tmp_fxr[:n]
	for i := 0; i < n; i++ {
		x := uint64(int32(t2[i])) << 22
		rt3[i] = fxr_of_scaled32(x)
	}
	vect_FFT(logn, rt3)
	rt2 := tmp_fxr[n : n+hn]
	copy(rt2, rt3[:hn])

	// Buffer contents:
	//   Fp    unreduced F (RNS+NTT) (n)
	//   Gp    unreduced G (RNS+NTT) (n)
	//   t1    F*adj(f) + G*adj(g) (plain, 32-bit) (n)
	// In tmp_fxr:
	//   rt3   free (n)
	//   rt2   f*adj(f) + g*adj(g) (FFT, self-ajdoint) (hn)

	// Convert F*adj(f) + G*adj(g) to FFT (scaled by 2^10) (into rt3).
	for i := 0; i < n; i++ {
		x := uint64(int32(t1[i])) << 22
		rt3[i] = fxr_of_scaled32(x)
	}
	vect_FFT(logn, rt3)

	// Divide F*adj(f) + G*adj(g) by f*adj(f) + g*adj(g) and round
	// the result into t1, with conversion to RNS.
	vect_div_selfadj_fft(logn, rt3, rt2)
	vect_iFFT(logn, rt3)
	for i := 0; i < n; i++ {
		t1[i] = mp_set(fxr_round(rt3[i]), p)
	}

	// Buffer contents:
	//   Fp    unreduced F (RNS+NTT) (n)
	//   Gp    unreduced G (RNS+NTT) (n)
	//   t1    k (RNS) (n)
	//   t2    free (n)
	//   t3    free (n)
	//   t4    free (n)

	// Convert k to RNS+NTT+Montgomery.
	mp_mkgm(logn, t4, primes[0].g, p, p0i)
	mp_NTT(logn, t1, t4, p, p0i)
	for i := 0; i < n; i++ {
		t1[i] = mp_mmul(t1[i], r2, p, p0i)
	}

	// Subtract k*f from F and k*g from G.
	// We also compute f*G - g*F (in RNS+NTT) to check that the solution
	// is correct.
	for i := 0; i < n; i++ {
		t2[i] = mp_set(int32(f[i]), p)
		t3[i] = mp_set(int32(g[i]), p)
	}
	mp_NTT(logn, t2, t4, p, p0i)
	mp_NTT(logn, t3, t4, p, p0i)
	rv := mp_mmul(q, 1, p, p0i)
	for i := 0; i < n; i++ {
		Fp[i] = mp_sub(Fp[i], mp_mmul(t1[i], t2[i], p, p0i), p)
		Gp[i] = mp_sub(Gp[i], mp_mmul(t1[i], t3[i], p, p0i), p)
		x := mp_sub(
			mp_mmul(t2[i], Gp[i], p, p0i),
			mp_mmul(t3[i], Fp[i], p, p0i), p)
		if x != rv {
			return false
		}
	}

	// Convert back F and G into normal representation.
	mp_mkigm(logn, t4, primes[0].ig, p, p0i)
	mp_iNTT(logn, Fp, t4, p, p0i)
	mp_iNTT(logn, Gp, t4, p, p0i)
	poly_mp_norm(logn, Fp, p)
	poly_mp_norm(logn, Gp, p)

	return true
}

// Solve the NTRU equation for the provided (f,g). The (F,G) solution,
// if found, is written into the provided arrays.
// Returned value is true on success, false on error.
//
// tmp[] must have room for 6*n words. tmp_fxr[] must have room for 2.5*n
// elements.
func solve_NTRU(logn uint,
	f []int8, g []int8, F []int8, G []int8, tmp []uint32, tmp_fxr []fxr) bool {

	n := 1 << logn

	if !solve_NTRU_deepest(logn, f, g, tmp) {
		return false
	}
	for depth := logn - 1; depth > 0; depth-- {
		if !solve_NTRU_intermediate(logn, f, g, depth, tmp, tmp_fxr) {
			return false
		}
	}
	if !solve_NTRU_depth0(logn, f, g, tmp, tmp_fxr) {
		return false
	}

	// F and G are at the start of tmp[] (plain, 31 bits per value).
	// We need to convert them to 8-bit representation, and check
	// that they are within the expected range.
	lim := int32(127)
	if !poly_big_to_small(logn, F, tmp, lim) {
		return false
	}
	if !poly_big_to_small(logn, G, tmp[n:], lim) {
		return false
	}
	return true
}

// Check that a given (f,g) has an acceptable orthogonolized norm.
// tmp_fxr[] must have room for 2.5*n fxr values.
func check_ortho_norm(logn uint, f []int8, g []int8, tmp_fxr []fxr) bool {
	n := 1 << logn
	rt1 := tmp_fxr[:n]
	rt2 := tmp_fxr[n : 2*n]
	rt3 := tmp_fxr[2*n:]
	vect_set(logn, rt1, f)
	vect_set(logn, rt2, g)
	vect_FFT(logn, rt1)
	vect_FFT(logn, rt2)
	vect_invnorm_fft(logn, rt3, rt1, rt2, 0)
	vect_adj_fft(logn, rt1)
	vect_adj_fft(logn, rt2)
	vect_mul_realconst(logn, rt1, fxr_of(12289))
	vect_mul_realconst(logn, rt2, fxr_of(12289))
	vect_mul_selfadj_fft(logn, rt1, rt3)
	vect_mul_selfadj_fft(logn, rt2, rt3)
	vect_iFFT(logn, rt1)
	vect_iFFT(logn, rt2)
	sn := fxr_ZERO
	for i := 0; i < n; i++ {
		sn = fxr_add(sn, fxr_add(fxr_sqr(rt1[i]), fxr_sqr(rt2[i])))
	}
	return fxr_lt(sn, fxr_of_scaled32(72251709809335))
}
