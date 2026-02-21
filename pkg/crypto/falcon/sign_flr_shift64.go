//go:build amd64 || arm64 || riscv64

package fndsa

// ursh, irsh and ulsh are functions to perform shifts with a potentially
// secret count. These versions are for 64-bit architectures, for which it
// is assumed that the plain shift operation is constant-time.
func ursh(x uint64, n uint32) uint64 {
	return x >> n
}
func irsh(x int64, n uint32) int64 {
	return x >> n
}
func ulsh(x uint64, n uint32) uint64 {
	return x << n
}
