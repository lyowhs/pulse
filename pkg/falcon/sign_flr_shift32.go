//go:build !(amd64 || arm64 || riscv64)

package fndsa

// ursh, irsh and ulsh are functions to perform shifts with a potentially
// secret count. Some 32-bit architectures use non-constant-time routines
// when shifting a 64-bit value, leaking whether the count was below 32
// or not.
func ursh(x uint64, n uint32) uint64 {
	x ^= (x ^ (x >> 32)) & -uint64(n>>5)
	return x >> (n & 0x1F)
}
func irsh(x int64, n uint32) int64 {
	x ^= (x ^ (x >> 32)) & -int64(n>>5)
	return x >> (n & 0x1F)
}
func ulsh(x uint64, n uint32) uint64 {
	x ^= (x ^ (x << 32)) & -uint64(n>>5)
	return x << (n & 0x1F)
}
