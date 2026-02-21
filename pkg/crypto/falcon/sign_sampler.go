package fndsa

import (
	"math/bits"
)

// 1/(2*(1.8205^2))
var inv_2sqrsigma0 = f64mk(5435486223186882, -55)

// For logn = 1 to 10, n = 2^logn:
//
//	q = 12289
//	gs_norm = (117/100)*sqrt(q)
//	bitsec = max(2, n/4)
//	eps = 1/sqrt(bitsec*2^64)
//	smoothz2n = sqrt(log(4*n*(1 + 1/eps))/pi)/sqrt(2*pi)
//	sigma = smoothz2n*gs_norm
//	sigma_min = sigma/gs_norm = smoothz2n
//
// We store precomputed values for 1/sigma and for sigma_min, indexed
// by logn.
var inv_sigma = []f64{
	f64_ZERO,                     // unused
	f64mk(7961475618707097, -60), // 0.0069054793295940881528
	f64mk(7851656902127320, -60), // 0.0068102267767177965681
	f64mk(7746260754658859, -60), // 0.0067188101910722700565
	f64mk(7595833604889141, -60), // 0.0065883354370073655600
	f64mk(7453842886538220, -60), // 0.0064651781207602890978
	f64mk(7319528409832599, -60), // 0.0063486788828078985744
	f64mk(7192222552237877, -60), // 0.0062382586529084365056
	f64mk(7071336252758509, -60), // 0.0061334065020930252290
	f64mk(6956347512113097, -60), // 0.0060336696681577231923
	f64mk(6846791885593314, -60), // 0.0059386453095331150985
}
var sigma_min = []f64{
	f64_ZERO,                     // unused
	f64mk(5028307297130123, -52), // 1.1165085072329102589
	f64mk(5098636688852518, -52), // 1.1321247692325272406
	f64mk(5168009084304506, -52), // 1.1475285353733668685
	f64mk(5270355833453349, -52), // 1.1702540788534828940
	f64mk(5370752584786614, -52), // 1.1925466358390344011
	f64mk(5469306724145091, -52), // 1.2144300507766139921
	f64mk(5566116128735780, -52), // 1.2359260567719808790
	f64mk(5661270305715104, -52), // 1.2570545284063214163
	f64mk(5754851361258101, -52), // 1.2778336969128335860
	f64mk(5846934829975396, -52), // 1.2982803343442918540
}

// Distribution for gaussian0() (this is the RCDT table from the
// specification, expressed in base 2^24).
var gaussian0_rcdt = []uint32{
	10745844, 3068844, 3741698,
	5559083, 1580863, 8248194,
	2260429, 13669192, 2736639,
	708981, 4421575, 10046180,
	169348, 7122675, 4136815,
	30538, 13063405, 7650655,
	4132, 14505003, 7826148,
	417, 16768101, 11363290,
	31, 8444042, 8086568,
	1, 12844466, 265321,
	0, 1232676, 13644283,
	0, 38047, 9111839,
	0, 870, 6138264,
	0, 14, 12545723,
	0, 0, 3104126,
	0, 0, 28824,
	0, 0, 198,
	0, 0, 1,
}

// log(2)
var log2 = f64mk(6243314768165359, -53)

// 1/log(2)
var inv_log2 = f64mk(6497320848556798, -52)

// Sampler state: a wrapper around a PRNG (SHAKE256-based), and also embedding
// the degree.
type sampler struct {
	pc   *shake256prng
	logn uint
}

// Initialize the sampler for a given degree and seed.
func newSampler(logn uint, seed []byte) *sampler {
	s := new(sampler)
	s.pc = newSHAKE256prng(seed)
	s.logn = logn
	return s
}

// Sample a small integer with a fixed half-Gaussian centred on zero;
// returned value is non-negative.
func (s *sampler) gaussian0() int32 {
	// Get a random 72-bit value, into three 24-bit limbs.
	lo := s.pc.next_u64()
	hi := s.pc.next_u8()
	v0 := uint32(lo) & 0xFFFFFF
	v1 := uint32(lo>>24) & 0xFFFFFF
	v2 := uint32(lo>>48) | (uint32(hi) << 16)

	// Output is z such that v0..v2 is lower than the first z elements
	// of the RCDT table. For constant-time processing, we always scan
	// the whole table.
	z := int32(0)
	for i := 0; i < len(gaussian0_rcdt); i += 3 {
		cc := (v0 - gaussian0_rcdt[i+2]) >> 31
		cc = (v1 - gaussian0_rcdt[i+1] - cc) >> 31
		cc = (v2 - gaussian0_rcdt[i+0] - cc) >> 31
		z += int32(cc)
	}
	return z
}

// The polynomial approximation of exp(-x) is from FACCT:
//
//	https://eprint.iacr.org/2018/1234
//
// Specifically, the values are extracted from the implementation
// referenced by the FACCT paper, available at:
//
//	https://github.com/raykzhao/gaussian
var expm_coeffs = []uint64{
	0x00000004741183A3,
	0x00000036548CFC06,
	0x0000024FDCBF140A,
	0x0000171D939DE045,
	0x0000D00CF58F6F84,
	0x000680681CF796E3,
	0x002D82D8305B0FEA,
	0x011111110E066FD0,
	0x0555555555070F00,
	0x155555555581FF00,
	0x400000000002B400,
	0x7FFFFFFFFFFF4800,
	0x8000000000000000,
}

// Given x and ccs, return ccs*exp(-x)*2^63, rounded to an integer.
// Assumptions:
//
//	0 <= x < log(2)
//	0 <= ccs <= 1
//
// Returned value is in [0,2^63] (but we cannot get the low values if
// ccs is not very close to 0).
func expm_p63(x f64, ccs f64) uint64 {
	y := expm_coeffs[0]
	z := f64_mtwop63(x) << 1
	w := f64_mtwop63(ccs) << 1

	// We assume that Mul64() is constant-time (see comments in
	// sign_flr_emu.go, function f64_mul()).
	for i := 1; i < len(expm_coeffs); i++ {
		c, _ := bits.Mul64(y, z)
		y = expm_coeffs[i] - c
	}
	c, _ := bits.Mul64(y, w)
	return c
}

// Sample a bit (true or false) with probability ccs*exp(-x) (for x >= 0).
func (s *sampler) ber_exp(x f64, ccs f64) bool {
	// Reduce x modulo log(2): x = t*log(2) + r, for some integer t,
	// and 0 <= r < log(2). Since x >= 0, we can use f64_trunc().
	ti := f64_trunc(f64_mul(x, inv_log2))
	r := f64_sub(x, f64_mul(f64_of_i32(ti), log2))

	// Saturate t to 63 (probability that t >= 64 is about 2^(-32) and in
	// that case ber_exp() should return true with probability less than
	// 2^(-64), hence that case is negligible in practice).
	t := uint32(ti)
	t |= (63 - t) >> 26
	t &= 63

	// Compute ccs*exp(-x) = (ccs*exp(-r))/2^t. We want the result scaled
	// up by a factor 2^64. Since expm_p63() returns a value that could be
	// equal to 2^63, we shift by 1 and subtract 1 to ensure we get no
	// overflow (bias is negligible).
	z := ursh((expm_p63(r, ccs)<<1)-1, t)

	// Sample a bit. We do a lazy byte-by-byte comparison of z with a
	// uniform 64-bit integer, consuming only as many bytes as necessary.
	// Since the PRNG is cryptographically strong, this leaks no information.
	for i := 56; i >= 0; i -= 8 {
		w := s.pc.next_u8()
		bz := uint8(z >> i)
		if w != bz {
			return w < bz
		}
	}
	return false
}

// Sample the next value. Parameters are the distribution centre (mu)
// and inverse of standard deviation (isigma); both vary (and are secret)
// within some given range.
func (s *sampler) next(mu f64, isigma f64) int32 {
	// Split centre mu into t + r, for integer t = floor(mu).
	t := f64_floor(mu)
	r := f64_sub(mu, f64_of_i32(t))

	// dss = 1/(2*sigma^2) = 0.5*(isigma^2)
	dss := f64_half(f64_sqr(isigma))

	// ccs = sigma_min / sigma = sigma_min * isigma
	ccs := f64_mul(isigma, sigma_min[s.logn])

	// We sample on centre r, and add t to the output.
	for {
		// Get z from a non-negative Gaussian distribution, then get a
		// random bit b to turn z into a sort-of bimodal distribution
		// by using z+1 if b = 1, or -z otherwise.
		z0 := s.gaussian0()
		b := int32(s.pc.next_u8()) & 1
		z := b + ((b<<1)-1)*z0

		// Rejection sampling.
		// We got z from:        G(z) = exp(-((z-b)^2)/(2*sigma0^2))
		// Target distribution:  S(z) = exp(-((z-r)^2)/(2*signa^2))
		// We apply an extra scaling ccs which increases the rejection rate
		// (hence decreases performance) but also ensures that measuring
		// the rejection rate does not leak enough information to attackers.
		x := f64_mul(f64_sqr(f64_sub(f64_of_i32(z), r)), dss)
		x = f64_sub(x, f64_mul(f64_of_i32(z0*z0), inv_2sqrsigma0))
		if s.ber_exp(x, ccs) {
			return t + z
		}
	}
}

// Fast Fourier sampling:
//
//	s               sampler (initialized)
//	t0, t1          target vector
//	g00, g01, g11   Gram matrix (G = [[g00, g01], [adj(g01), g11]])
//	tmp             temporary (at least 4*n elements)
//
// Output is written back into t0 and t1. g00, g01 and g11 are consumed.
// All polynomials are in FFT representation.
func (s *sampler) ffsamp_fft(
	t0 []f64, t1 []f64, g00 []f64, g01 []f64, g11 []f64, tmp []f64) {

	s.ffsamp_fft_inner(s.logn, t0, t1, g00, g01, g11, tmp)
}

// Inner function for fast Fourier sampling (recursive).
func (s *sampler) ffsamp_fft_inner(logn uint,
	t0 []f64, t1 []f64, g00 []f64, g01 []f64, g11 []f64, tmp []f64) {

	// Recursion bottom is when we reached degree-2 polynomials; the
	// final steps are unrolled.
	if logn == 1 {
		// Decompose G into LDL. g00 and g01 are self-adjoint.
		g00_re := g00[0]
		g01_re := g01[0]
		g01_im := g01[1]
		g11_re := g11[0]
		inv_g00_re := f64_inv(g00_re)
		mu_re := f64_mul(g01_re, inv_g00_re)
		mu_im := f64_mul(g01_im, inv_g00_re)
		zo_re := f64_add(f64_mul(mu_re, g01_re), f64_mul(mu_im, g01_im))
		d00_re := g00_re
		l01_re := mu_re
		l01_im := f64_neg(mu_im)
		d11_re := f64_sub(g11_re, zo_re)

		// No split on d00 and d11 (each has a unique coefficient).
		// t1 split is trivial.
		w0 := t1[0]
		w1 := t1[1]
		leaf := f64_mul(f64_sqrt(d11_re), inv_sigma[s.logn])
		y0 := f64_of_i32(s.next(w0, leaf))
		y1 := f64_of_i32(s.next(w1, leaf))

		// Merge is trivial.

		a_re := f64_sub(w0, y0)
		a_im := f64_sub(w1, y1)
		b_re, b_im := flc_mul(a_re, a_im, l01_re, l01_im)
		x0 := f64_add(t0[0], b_re)
		x1 := f64_add(t0[1], b_im)
		t1[0] = y0
		t1[1] = y1

		// Second unrolled recursion, on the split tb0.
		leaf = f64_mul(f64_sqrt(d00_re), inv_sigma[s.logn])
		t0[0] = f64_of_i32(s.next(x0, leaf))
		t0[1] = f64_of_i32(s.next(x1, leaf))

		return
	}

	// General case: logn >= 2.
	n := 1 << logn
	hn := n >> 1

	// Decompose G into LDL; the decomposition replaces G.
	fpoly_LDL_fft(logn, g00, g01, g11)

	// Split d00 and d11 (currently in g00 and g11) and expand them
	// into half-size quasi-cyclic Gram matrices. We also save l10
	// (currently in g01) into tmp.
	w0 := tmp[:hn]
	w1 := tmp[hn:n]
	fpoly_split_selfadj_fft(logn, w0, w1, g00)
	copy(g00[:n], w0[:n])
	fpoly_split_selfadj_fft(logn, w0, w1, g11)
	copy(g11[:hn], w0)
	copy(g11[hn:n], w1)
	copy(tmp[:n], g01[:n])
	copy(g01[:hn], g00[:hn])
	copy(g01[hn:n], g11[:hn])

	// The half-size Gram matrices for the recursive LDL tree
	// exploration are now:
	//   - left sub-tree:   g00[0..hn], g00[hn..n], g01[0..hn]
	//   - right sub-tree:  g11[0..hn], g11[hn..n], g01[hn..n]
	// l10 is in tmp[0..n].
	left_00 := g00[:hn]
	left_01 := g00[hn:n]
	right_00 := g11[:hn]
	right_01 := g11[hn:n]
	left_11 := g01[:hn]
	right_11 := g01[hn:n]

	// We split t1 and use the first recursive call on the two
	// halves, using the right sub-tree. The result is merged
	// back into tmp[2*n..3*n].
	w0 = tmp[n : n+hn]
	w1 = tmp[n+hn : n*2]
	w2 := tmp[n*2:]
	fpoly_split_fft(logn, w0, w1, t1)
	s.ffsamp_fft_inner(logn-1, w0, w1, right_00, right_01, right_11, w2)
	fpoly_merge_fft(logn, w2, w0, w1)

	// At this point:
	//   t0 and t1 are unmodified
	//   l10 is in tmp[0..n]
	//   z1 is in tmp[2*n..3*n]
	// We compute tb0 = t0 + (t1 - z1)*l10.
	// tb0 is written over t0.
	// z1 is moved into t1.
	// l10 is scratched.
	l10 := tmp[:n]
	w := tmp[n : n*2]
	z1 := tmp[n*2 : n*3]
	copy(w, t1[:n])
	fpoly_sub(logn, w, z1)
	copy(t1[:n], z1)
	fpoly_mul_fft(logn, l10, w)
	fpoly_add(logn, t0, l10)

	// Second recursive invocation, on the split tb0 (currently in t0),
	// using the left sub-tree.
	// tmp is free.
	w0 = tmp[:hn]
	w1 = tmp[hn:n]
	w2 = tmp[n:]
	fpoly_split_fft(logn, w0, w1, t0)
	s.ffsamp_fft_inner(logn-1, w0, w1, left_00, left_01, left_11, w2)
	fpoly_merge_fft(logn, t0, w0, w1)
}
