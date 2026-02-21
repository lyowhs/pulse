//go:build !fndsa_fp_emu && 386.sse2

// f64_mtwop63(x) returns floor(x*2^63) for x in [0,1[.
// This implementation is for non-emulated 386 architectures, where there
// is no opcode for converting a floating-point value to a 64-bit integer;
// instead, we need to use three smaller conversions to 32-bit integers.

package fndsa

func f64_mtwop63(x f64) uint64 {
	// We do three multiplications by 2^21 to get the result in base 2^21.
	// Note that since each conversion to int32 is rounded toward 0, it
	// is guaranteed that successive values of x are non-negative, and all
	// subtractions and multiplications are exact.
	x = float64(x * 2097152.0)
	z2 := int32(x)
	x = float64(x - float64(z2))
	x = float64(x * 2097152.0)
	z1 := int32(x)
	x = float64(x - float64(z1))
	x = float64(x * 2097152.0)
	z0 := int32(x)

	r2 := uint32(z2)
	r1 := uint32(z1)
	r0 := uint32(z0)
	return (uint64(r2) << 42) + (uint64(r1) << 21) + uint64(r0)
}
