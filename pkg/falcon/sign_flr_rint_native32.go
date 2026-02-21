//go:build !fndsa_fp_emu && 386.sse2 && gccgo

// f64_rint(x) rounds x to the nearest 32-bit integer; input must be less
// than 2^31 in absolute value.
// This implementation is for native 32-bit implementations but without
// access to assembly (because gccgo is used).

package fndsa

func f64_rint(x f64) int32 {
	// We cannot use the method of the native non-assembly f64_rint()
	// for 64-bit architectures because we do not have access to a
	// proper (constant-time) conversion from floating-point to a 64-bit
	// integer. Instead, we must first do a truncating conversion, and
	// then finish the rounding using the raw representation of the
	// fractional part.

	// Get the value as a truncated integer, and extract the fractional
	// part. The subtraction is exact.
	z := int32(x)
	y := float64(x - float64(z))

	// If abs(y) < 0.5 then z is correct; otherwise, we must move z one
	// unit away from 0 (the direction depends on the sign of y). We use
	// the fact that if we mask out the sign bit, then the raw representation
	// order matches the value order.
	// Raw representation of 0.5 has mantissa zero and encoded exponent 1022.
	// We set am to -1 if z must be adjusted, 0 otheriwse.
	v := f64_to_bits(y)
	w := v & m63
	am := int32((w-(uint64(1022)<<52))>>63) - 1

	// Adjustment of z, if needed, must be +1 if y is non-negative,
	// -1 otherwise. We compute the opposite adjustment by applying the
	// sign bit of y to am.
	sv := int32(int64(v) >> 63)
	a := (am ^ sv) - sv
	return z - a
}
