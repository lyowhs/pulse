//go:build !fndsa_fp_emu && (386.sse2 || amd64 || arm64 || riscv64)

package fndsa

import (
	"math"
)

type f64 = float64

const f64_ZERO = 0.0

var f64_NZERO = math.Float64frombits(0x8000000000000000)

const f64_ONE = 1.0

// Make a f64 value equal to i*2^e. The integer i MUST be such that
// 2^52 <= abs(i) < 2^53, and the exponent MUST be in-range. This is
// meant for tables of constants.
func f64mk(i int64, e int32) f64 {
	return math.Ldexp(float64(i), int(e))
}

// Convert a f64 value to its 64-bit representation.
func f64_to_bits(x f64) uint64 {
	return math.Float64bits(x)
}

// Make a f64 value from its 64-bit representation.
func f64_from_bits(v uint64) f64 {
	return math.Float64frombits(v)
}

// Convert integer i to a floating-point value (with appropriate rounding).
// The source integer MUST NOT be equal to -2^63. This function needs not
// be constant-time.
func f64_of(i int64) f64 {
	return float64(i)
}

// Same as f64_of() but input is 32-bit. This function MUST be constant-time.
func f64_of_i32(i int32) f64 {
	return float64(i)
}

// Given integer i and scale sc, return i*2^sc. Source integer MUST be
// in the [-(2^63-1), +(2^63-1)] range (i.e. value -2^63 is forbidden).
func f64_scaled(i int64, sc int32) f64 {
	return math.Ldexp(float64(i), int(sc))
}

// f64_rint() is implemented either in assembly or with native code:
//    sign_flr_rint_native.go
//    sign_flr_XXX.s and sign_flr_asm.go

// f64_floor() is implemented either in assembly or with native code:
//    sign_flr_floor_native.go
//    sign_flr_XXX.s and sign_flr_asm.go

// Round a value toward zero. Source value must be less than 2^31 in
// absolute value.
func f64_trunc(x f64) int32 {
	return int32(x)
}

// f64_mtwop63() has two native implementations:
//    sign_flr_mtwop63_native.go   for 64-bit architectures
//    sign_flr_mtwop63_spec.go     for 32-bit architectures (386.sse2)

// Addition.
func f64_add(x f64, y f64) f64 {
	return float64(x + y)
}

// Subtraction.
func f64_sub(x f64, y f64) f64 {
	return float64(x - y)
}

// Negation.
func f64_neg(x f64) f64 {
	return float64(-x)
}

// Halving.
func f64_half(x f64) f64 {
	return float64(x * 0.5)
}

// Doubling.
func f64_double(x f64) f64 {
	return float64(x * 2.0)
}

// Multiplication.
func f64_mul(x f64, y f64) f64 {
	return float64(x * y)
}

// Squaring.
func f64_sqr(x f64) f64 {
	return float64(x * x)
}

// Division.
func f64_div(x f64, y f64) f64 {
	return float64(x / y)
}

// Inversion.
func f64_inv(x f64) f64 {
	return float64(1.0 / x)
}

var inv_pow2 = []float64{
	1.00000000000,
	0.50000000000,
	0.25000000000,
	0.12500000000,
	0.06250000000,
	0.03125000000,
	0.01562500000,
	0.00781250000,
	0.00390625000,
	0.00195312500,
	0.00097656250,
}

// f64_sqrt() is implemented either in assembly or with native code:
//    sign_flr_sqrt_native.go
//    sign_flr_XXX.s and sign_flr_proto.go

// Divide value by 2^e.
func f64_div2e(x f64, e uint32) f64 {
	return float64(x * inv_pow2[uint(e)])
}

// Get the absolute value.
func f64_abs(x f64) f64 {
	return math.Float64frombits(math.Float64bits(x) & 0x7FFFFFFFFFFFFFFF)
}
