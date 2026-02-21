//go:build !fndsa_fp_emu && (amd64 || arm64 || riscv64)

// f64_mtwop63(x) returns floor(x*2^63) for x in [0,1[.
// This implementation is for 64-bit platforms with native floating-point
// and a native conversion opcode.

package fndsa

func f64_mtwop63(x f64) uint64 {
	return uint64(int64(f64_mul(x, 9223372036854775808.0)))
}
