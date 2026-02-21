//go:build fndsa_fp_emu || !(386.sse2 || amd64 || arm64 || riscv64)

package fndsa

import (
	"math/bits"
)

type f64 = uint64

const f64_ZERO = f64(0)
const f64_NZERO = f64(0x8000000000000000)
const f64_ONE = uint64(1023) << 52

// Make a f64 value equal to i*2^e. The integer i MUST be such that
// 2^52 <= abs(i) < 2^53, and the exponent MUST be in-range. This is
// meant for tables of constants.
func f64mk(i int64, e int32) f64 {
	ee := uint64((uint32(e)+1075)&0x7FF) << 52
	if i < 0 {
		return ee + (uint64(-i) & 0x000FFFFFFFFFFFFF) + 0x8000000000000000
	} else {
		return ee + (uint64(i) & 0x000FFFFFFFFFFFFF)
	}
}

// Convert a f64 value to its 64-bit representation.
func f64_to_bits(x f64) uint64 {
	return x
}

// Make a f64 value from its 64-bit representation.
func f64_from_bits(v uint64) f64 {
	return v
}

// Make a value out of the sign bit s, exponent e, and mantissa m.
// Rules:
//
//	only the low bit of s is used (0 or 1), other bits are ignored
//	it is assumed that no exponent overflow occurs
//	For a zero value:
//	   m = 0
//	   e = -1076
//	For a non-zero value:
//	   2^54 <= m < 2^55
//	   value is (-1)^s * 2^e * m, with proper rounding applied.
func f64_build(s uint64, e int32, m uint64) f64 {
	eu := uint32(e + 1076)
	cc := uint64((uint32(0xC8) >> (uint32(m) & 7)) & 1)
	return (s << 63) + (uint64(eu) << 52) + (m >> 2) + cc
}

// Like f64_build(), but it tolerates any value of e when m = 0. The
// other rules still apply.
func f64_build_z(s uint64, e int32, m uint64) f64 {
	eu := uint32(e+1076) & -uint32(m>>54)
	cc := uint64((uint32(0xC8) >> (uint32(m) & 7)) & 1)
	return (s << 63) + (uint64(eu) << 52) + (m >> 2) + cc
}

// Count of leading zeros in a 64-bit non-zero word.
func lzcnt_nonzero(x uint64) uint32 {
	// First step: if x >= 2^32, then set bit 5 in result, and shift x by
	// 32 bits; otherwise, keep it unchanged.
	y5 := x >> 32
	m5 := uint32((y5 - 1) >> 32)
	r := m5 & 0x20
	x4 := uint32(y5) | (m5 & uint32(x))

	// We now count leading zeros in x4, to add to the value in r.
	// We aply the same process for bits 4 to 1 of r, keeping to uint32.
	y4 := x4 >> 16
	m4 := (y4 - 1) >> 16
	r |= m4 & 0x10
	x3 := y4 | (m4 & x4)

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

	// Value x0 now fits on 2 bits. Since (by assumption) it is non-zero,
	// its value is either 1, 2 or 3; we only have to check its bit 1.
	return r + 1 - (x0 >> 1)
}

// Adjust m and e such that m*2^e is preserved, and m is in [2^63,2^64-1].
// If, on input, m is 0, then on output it is still 0, and e is replaced
// with e-63.
func norm64(m uint64, e int32) (uint64, int32) {
	c := lzcnt_nonzero(m | 1)
	return ulsh(m, c), e - int32(c)
}

// Convert integer i to a floating-point value (with appropriate rounding).
// The source integer MUST NOT be equal to -2^63. This function needs not
// be constant-time.
func f64_of(i int64) f64 {
	return f64_scaled(i, 0)
}

// Same as f64_of() but input is 32-bit. This function MUST be constant-time.
func f64_of_i32(i int32) f64 {
	return f64_scaled(int64(i), 0)
}

// Given integer i and scale sc, return i*2^sc. Source integer MUST be
// in the [-(2^63-1), +(2^63-1)] range (i.e. value -2^63 is forbidden).
func f64_scaled(i int64, sc int32) f64 {
	// Get sign mask and absolute value.
	s := uint64(i >> 63)
	m := (uint64(i) ^ s) - s

	// Normalize m to [2^63,2^64-1]
	m, sc = norm64(m, sc)

	// Divide m by 2^9; the least significant bit is sticky.
	sc += 9
	m = (m | ((m & 0x1FF) + 0x1FF)) >> 9

	// If input was zero then m = 0 at this point; otherwise, m is in
	// [2^54,2^55-1].
	return f64_build_z(s, sc, m)
}

// Round a value to the nearest 32-bit integer (roundTiesToEven policy).
// The input MUST be less than 2^31 in absolute value.
func f64_rint(x f64) int32 {
	// Extract the mantissa as a 64-bit integer.
	m := ((x << 10) | b62) & m63
	e := 1085 - (int32(x>>52) & 0x7FF)

	// If a shift of more than 63 bits is needed, then set m to 0. This
	// also covers the case of an input equal to zero.
	m &= uint64(int64(e-64) >> 16)
	eu := uint32(e) & 63

	// m should be right-shifted by e bits.
	// To apply proper rounding, we need to get the dropped bits and
	// apply the usual "sticky bit" rule.
	z := ulsh(m, 63-eu)
	y := ((z & m62) + m62) >> 1
	cc := uint64((uint32(0xC8) >> uint32((z|y)>>61)) & 1)

	// Shift and round.
	m = ursh(m, eu) + cc

	// Apply the sign.
	s := uint64(int64(x) >> 63)
	return int32((m ^ s) - s)
}

// Round a value toward -infinity. Source value must be less than 2^31 in
// absolute value.
func f64_floor(x f64) int32 {
	// Mantissa is extracted as in f64_rint(), but we apply the sign bit
	// immediately; truncation from the integer shift will then yield the
	// proper result.
	m := ((x << 10) | b62) & m63
	s := uint64(int64(x) >> 63)
	m = (m ^ s) - s

	// Get the shift count.
	e := 1085 - (int32(x>>52) & 0x7FF)

	// If the shift count is 64 or more, then the value should be 0 or -1,
	// depending on the sign bit. Note that we round "minus zero" to -1.
	// We only need to saturate the shift count at 63.
	eu := uint32(e)
	eu = (eu | ((63 - eu) >> 16)) & 63
	return int32(irsh(int64(m), eu))
}

// Round a value toward zero. Source value must be less than 2^31 in
// absolute value.
func f64_trunc(x f64) int32 {
	// This is the same method as in f64_floor(), but applying the sign
	// after the shift instead of before.
	m := ((x << 10) | b62) & m63
	e := 1085 - (int32(x>>52) & 0x7FF)
	eu := uint32(e)
	eu = (eu | ((63 - eu) >> 16)) & 63
	m = uint64(irsh(int64(m), eu))

	s := uint64(int64(x) >> 63)
	return int32((m ^ s) - s)
}

// For 0 <= x < 1, return floor(x*2^63).
func f64_mtwop63(x f64) uint64 {
	// Multiply by 2^63, then apply the same method as in f64_floor();
	// we can ignore the sign bit since the input is assumed non-negative.
	// The multiplication by 2^63 is merged implicitly in the exponent
	// processing.
	v := f64_to_bits(x)
	m := ((v << 10) | b62) & m63
	e := 1022 - (int32(v>>52) & 0x7FF)
	eu := uint32(e)
	eu = (eu | ((63 - eu) >> 16)) & 63
	return ursh(m, eu)
}

// Addition.
func f64_add(x f64, y f64) f64 {
	// Get both operands as x and y, and such that x has the greater
	// absolute value of the two. If x and y have the same absolute
	// value and different signs, when we want x to be the positive
	// value. This guarantees the following:
	//   - Exponent of y is not greater than exponent of x.
	//   - Result has the sign of x.
	// The special case for identical absolute values is for adding
	// z with -z for some value z. Indeed, if abs(x) = abs(y), then
	// the following situations may happen:
	//    x > 0, y = x    -> result is positive
	//    x < 0, y = x    -> result is negative
	//    x > 0, y = -x   -> result is +0
	//    x < 0, y = -x   -> result is +0   (*)
	//    x = +0, y = +0  -> result is +0
	//    x = +0, y = -0  -> result is +0
	//    x = -0, y = +0  -> result is +0   (*)
	//    x = -0, y = -0  -> result is -0
	// Enforcing a swap when absolute values are equal but the sign of
	// x is 1 (negative) avoids the two situations tagged '(*)' above.
	// For all other situations, the result indeed has the sign of x.
	//
	// Note that for positive values, the numerical order of encoded
	// exponent||mantissa values matches the order of the encoded
	// values.
	za := (x & m63) - (y & m63)
	za |= ((za - 1) & x)
	sw := (x ^ y) & uint64(int64(za)>>63)
	x ^= sw
	y ^= sw

	// Extract sign bits, exponents and mantissas. The mantissas are
	// scaled up to [2^55,2^56-1] and the exponent is unbiased. If
	// an operand is 0, then its mantissa is set to 0 at this step,
	// and its unbiased exponent is -1078.
	ex := uint32(x >> 52)
	sx := ex >> 11
	ex &= 0x7FF
	xu := ((x & m52) << 3) | (uint64((ex+0x7FF)>>11) << 55)
	ex -= 1078

	ey := uint32(y >> 52)
	sy := ey >> 11
	ey &= 0x7FF
	yu := ((y & m52) << 3) | (uint64((ey+0x7FF)>>11) << 55)
	ey -= 1078

	// x has the larger exponent, hence we only need to right-shift y.
	// If the shift count is larger than 59 then we clamp the value
	// to 0.
	n := ex - ey
	yu &= uint64(int64(int32(n)-60) >> 16)
	n &= 63

	// Right-shift yu by n bits; the lowest bit of yu is sticky.
	m := ulsh(1, n) - 1
	yu = ursh(yu|((yu&m)+m), n)

	// Add of subtract the mantissas, depending on the sign bits.
	dm := -uint64(sx ^ sy)
	zu := xu + yu - (dm & (yu << 1))

	// The result may be smaller than abs(x), or slightly larger, though
	// no more than twice larger. We normalize to [2^63, 2^64-1], then
	// shrink back to [2^54,2^55-1] (with a sticky bit).
	zu, e := norm64(zu, int32(ex))
	zu = (zu | ((zu & 0x1FF) + 0x1FF)) >> 9
	e += 9

	// Result uses the sign of x.
	return f64_build_z(uint64(sx), e, zu)
}

// Subtraction.
func f64_sub(x f64, y f64) f64 {
	return f64_add(x, y^b63)
}

// Negation.
func f64_neg(x f64) f64 {
	return x ^ b63
}

// Halving.
func f64_half(x f64) f64 {
	// We just subtract 1 from the exponent, except when the value is zero.
	// If the value is 0, then the subtraction overflows the exponent field
	// and the borrow flips the sign bit.
	y := x - b52
	return y + (((x ^ y) >> 11) & b52)
}

// Doubling.
func f64_double(x f64) f64 {
	// We add 1 to the exponent field, unless the value is zero.
	d := ((x & 0x7FF0000000000000) + 0x7FF0000000000000) >> 11
	return x + (d & b52)
}

// Multiplication.
func f64_mul(x f64, y f64) f64 {
	// Extract absolute values of mantissas, assuming non-zero
	// operands, and multiply them together.
	xu := (x & m52) | b52
	yu := (y & m52) | b52

	// Compute the product over 128 bits, then divide by 2^50 to get
	// a result in zu; we drop the low 50 bits, except that we force
	// the lowest bit of zu to 1 if any of the dropped bits is non-zero
	// (sticky bit processing).
	// Go's standard library documentation promises that Mul64()'s
	// "execution time does not depend on the inputs". That promise is
	// somewhat optimistic since there is existing hardware for which
	// the CPU's multiplication opcodes are not constant-time (e.g.
	// ARM Cortex-A53 and A55 CPUs return early on 64-bit multiplies
	// when the operands fit on 32 bits). But in general this is true
	// and we'll assume it for now.
	zhi, zlo := bits.Mul64(xu, yu)
	zu := (zlo >> 50) | (zhi << 14)
	zu |= ((zlo & m50) + m50) >> 50

	// If zu is in [2^55,2^56-1] then right-shift it by 1 bit.
	// lsb is sticky and must be preserved if non-zero.
	es := uint32(zu >> 55)
	zu = (zu >> es) | (zu & 1)

	// Aggregate scaling factor:
	//  - Each source exponent is biased by 1023.
	//  - Integral mantiassas are scaled by 2^52, hence an extra 52
	//    bias for each exponent.
	//  - However, we right-shifted z by 50 + es.
	// In total: we add exponents, then subtract 2*(1023 + 52),
	// then add 50 + es.
	ex := uint32(x>>52) & 0x7FF
	ey := uint32(y>>52) & 0x7FF
	e := ex + ey - 2100 + es

	// Sign bit is the XOR of the operand sign bits.
	s := (x ^ y) >> 63

	// Corrective action for zeros: if either of the operands is zero,
	// then the computations above are wrong and we must clear the
	// mantissa and adjust the exponent.
	dzu := uint32(int32((ex-1)|(ey-1)) >> 31)
	e ^= dzu & (e ^ uint32(0x100000000-1076))
	zu &= uint64(dzu&1) - 1
	return f64_build(s, int32(e), zu)
}

// Squaring.
func f64_sqr(x f64) f64 {
	return f64_mul(x, x)
}

// Division.
func f64_div(x f64, y f64) f64 {
	// Ensure that we work on the raw representations.
	xv := f64_to_bits(x)
	yv := f64_to_bits(y)

	// Extract mantissas (unsigned).
	xu := (xv & m52) | b52
	yu := (yv & m52) | b52

	// Perform bit-by-bit division of xu by yu; we run it for 55 bits.
	q := uint64(0)
	for i := 0; i < 55; i++ {
		b := ((xu - yu) >> 63) - 1
		xu -= b & yu
		q |= b & 1
		xu <<= 1
		q <<= 1
	}

	// 55-bit quotient is in q, with an extra multiplication by 2.
	// Set the lsb to 1 if xu is non-zero at this point (sticky bit).
	q |= (xu | -xu) >> 63

	// Quotient is at most 2^56-1, but cannot be lower than 2^54 since
	// both operands to the loop were in [2^52,2^53-1]. This is
	// similar to the situation in f64_mul().
	es := uint32(q >> 55)
	q = (q >> es) | (q & 1)

	// Aggregate scaling factor.
	ex := uint32(xv>>52) & 0x7FF
	ey := uint32(yv>>52) & 0x7FF
	e := ex - ey - 55 + es

	// Sign bit is the XOR of the operand sign bits.
	s := (xv ^ yv) >> 63

	// Corrective action for zeros: if x was zero, then the
	// computations above are wrong and we must clear the mantissa
	// and adjust the exponent. Since we do not support infinites,
	// we assume that y (divisor) was not zero.
	dzu := uint32(int32(ex-1) >> 31)
	e ^= dzu & (e ^ uint32(0x100000000-1076))
	dm := uint64(dzu&1) - 1
	s &= dm
	q &= dm
	return f64_build(s, int32(e), q)
}

// Inversion.
func f64_inv(x f64) f64 {
	return f64_div(f64_ONE, x)
}

// Square root.
func f64_sqrt(x f64) f64 {
	// Extract exponent and mantissa. By assumption, the operand is
	// non-negative, hence we can ignore the sign bit (we must still
	// mask it out because sqrt() should work on -0.0). We want the
	// "true" exponent corresponding to a mantissa between 1 (inclusive)
	// and 2 (exclusive).
	xu := (x & m52) | b52
	ex := uint32(x>>52) & 0x7FF
	e := int32(ex) - 1023

	// If the exponent is odd, then we doulbe the mantissa, and subtract
	// 1 from the exponent. We can then halve the exponent.
	xu += xu & -uint64(uint32(e)&1)
	e >>= 1

	// Double the mantissa to make it an integer in [2^53,2^55-1].
	xu <<= 1

	// xu represents an integer between 1 (inclusive) and 4
	// (exclusive) in a fixed-point notation (53 fractional bits).
	// We compute the square root bit by bit.
	q := uint64(0)
	s := uint64(0)
	r := b53
	for i := 0; i < 54; i++ {
		t := s + r
		b := ((xu - t) >> 63) - 1
		s += b & (r << 1)
		xu -= t & b
		q += r & b
		xu <<= 1
		r >>= 1
	}

	// Now q is a rounded-low 54-bit value, with a leading 1, then
	// 52 fractional digits, and an additional guard bit. We add an
	// extra sticky bit to account for what remains of the operand.
	q <<= 1
	q |= (xu | -xu) >> 63

	// Result q is in [2^54,2^55-1]; we bias the exponent by 54 bits
	// (since the computed e is, at this point, the "true" exponent).
	e -= 54

	// If the source value was zero, then we computed the square root
	// of 2^53 and set the exponent to -512, both of which are wrong
	// and must be corrected.
	q &= -uint64((ex + 0x7FF) >> 11)
	return f64_build_z(0, e, q)
}

// Divide value by 2^e. Value e must be in [0,10].
func f64_div2e(x f64, e uint32) f64 {
	ee := uint64(e) << 52
	y := x - ee
	ov := x ^ y
	return y + (ee & uint64(int64(ov)>>11))
}

// Multiply value by 2^63.
func f64_mul2e(x f64) f64 {
	// We add 63 to the exponent field, except if that field was zero,
	// because the double of zero is still zero.
	d := uint64(int64((x&0x7FF0000000000000)-b52) >> 12)
	return x + ((uint64(63) << 52) & ^d)
}

// Get the absolute value.
func f64_abs(x f64) f64 {
	return x & m63
}
