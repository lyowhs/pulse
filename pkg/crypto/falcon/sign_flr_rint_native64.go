//go:build !fndsa_fp_emu && (amd64 || arm64 || riscv64) && gccgo

// f64_rint(x) rounds x to the nearest 32-bit integer; input must be less
// than 2^31 in absolute value.
// This implementation is for native 64-bit implementations but without
// access to assembly (because gccgo is used).

package fndsa

func f64_rint(x f64) int32 {
	// We want to avoid the standard library function because it might
	// not be constant-time. Instead, we apply the following method.
	// Suppose that x >= 0; we know that x < 2^52. Computing x + 2^52 will
	// yield a value that will be rounded to the nearest integer with
	// exactly the right rules.
	// We still have to do it twice, to cover the case of x < 0.
	rp := int32(int64(float64(x+4503599627370496.0)) - 4503599627370496)
	rn := int32(int64(float64(x-4503599627370496.0)) + 4503599627370496)

	// If x >= 0 then the result is rp; otherwise, the result is rn.
	sx := int32(int64(f64_to_bits(x)) >> 63)
	return rp ^ (sx & (rp ^ rn))
}
