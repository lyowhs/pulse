//go:build !fndsa_fp_emu && (386.sse2 || amd64 || arm64 || riscv64) && gccgo

// f64_sqrt() computes a square root. This implementation calls the
// standard library implementation, which the compiler (gccgo) should
// translate into using the raw hardware opcode (FIXME: check that it
// is true).

package fndsa

import (
	"math"
)

func f64_sqrt(x f64) f64 {
	return float64(math.Sqrt(x))
}
