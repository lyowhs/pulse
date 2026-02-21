//go:build !fndsa_fp_emu && (386.sse2 || amd64 || arm64 || riscv64) && gccgo

// f64_floor(x) rounds x to an integer toward -infinity; input must be less
// than 2^31 in absolute value.
// This implementation is for native implementations but without access to
// assembly (because gccgo is used).

package fndsa

func f64_floor(x f64) int32 {
	// Perform conversion with rounding toward 0, then subtract 1 if
	// the result is greater than the source, which can happen only if
	// the source is negative. We use the fact that the order on bit
	// patterns matches the order on floating-point values when the sign
	// bit is zero (and the reverse order when the sign bit is one).
	r := int32(x)
	y := float64(r)
	xv := f64_to_bits(x)
	yv := f64_to_bits(y)
	return r - int32((((yv-xv)&xv&yv)|(xv^yv))>>63)
}
