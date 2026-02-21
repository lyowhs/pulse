//go:build !gccgo && !fndsa_fp_emu && (386.sse2 || amd64 || arm64 || riscv64)

// This file declares the prototypes for the assembly implementations of
// f64_rint(), f64_floor() and f64_sqrt(), which are used for the few
// recognized architecture.

package fndsa

// Round a value to the nearest 32-bit integer (roundTiesToEven policy).
// The input must be less than 2^31 in absolute value.
func f64_rint(x f64) int32

// Round a value toward -infinity. Source value must be less than 2^31 in
// absolute value.
func f64_floor(x f64) int32

// Square root.
func f64_sqrt(x f64) f64
