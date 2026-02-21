package fndsa

import (
	"testing"
	sha3 "golang.org/x/crypto/sha3"
)

func TestSigningKeySize(t *testing.T) {
	var expected = [11]int{
		0, 0, 13, 25, 49, 97, 177, 353, 641, 1281, 2305,
	}
	for logn := uint(2); logn <= 10; logn++ {
		s := SigningKeySize(logn)
		if s != expected[logn] {
			t.Fatalf("ERR: logn=%d -> %d (exp: %d)\n", logn, s, expected[logn])
		}
	}
}

func TestVerifyingKeySize(t *testing.T) {
	var expected = [11]int{
		0, 0, 8, 15, 29, 57, 113, 225, 449, 897, 1793,
	}
	for logn := uint(2); logn <= 10; logn++ {
		s := VerifyingKeySize(logn)
		if s != expected[logn] {
			t.Fatalf("ERR: logn=%d -> %d (exp: %d)\n", logn, s, expected[logn])
		}
	}
}

func TestSignatureSize(t *testing.T) {
	var expected = [11]int{
		0, 0, 47, 52, 63, 82, 122, 200, 356, 666, 1280,
	}
	for logn := uint(2); logn <= 10; logn++ {
		s := SignatureSize(logn)
		if s != expected[logn] {
			t.Fatalf("ERR: logn=%d -> %d (exp: %d)\n", logn, s, expected[logn])
		}
	}
}

// A PRNG based on four parallel SHAKE256 instances, with interleaved
// outputs.
//
// In general this is not better than a single SHAKE256, but it can yield
// some speed-ups when used with SIMD opcodes that can run the four
// SHAKE instances at the same time (e.g. AVX2 on x86 systems). It used
// to be part of the main implementation; it is retained here because
// some internal test vectors were generated with it.
type shake256x4 struct {
	state [4]sha3.ShakeHash
	buf   [4 * 136]byte
	ptr   int
}

// Create a new SHAKE256x4 instance, initialized with the provided seed.
func newSHAKE256x4(seed []byte) *shake256x4 {
	r := new(shake256x4)
	for i := 0; i < 4; i++ {
		var tmp [1]byte
		tmp[0] = byte(i)
		r.state[i] = sha3.NewShake256()
		r.state[i].Write(seed)
		r.state[i].Write(tmp[:])
	}
	r.ptr = len(r.buf)
	return r
}

// Get next byte from a SHAKE256x4 instance.
func (r *shake256x4) next_u8() uint8 {
	ptr := r.ptr
	if ptr == len(r.buf) {
		r.refill()
		ptr = 0
	}
	r.ptr = ptr + 1
	return r.buf[ptr]
}

// Get next 16-bit value from a SHAKE256x4 instance.
func (r *shake256x4) next_u16() uint16 {
	ptr := r.ptr
	if ptr >= (len(r.buf) - 1) {
		r.refill()
		ptr = 0
	}
	r.ptr = ptr + 2
	return uint16(r.buf[ptr]) + (uint16(r.buf[ptr+1]) << 8)
}

// Get next 64-bit value from a SHAKE256x4 instance.
func (r *shake256x4) next_u64() uint64 {
	ptr := r.ptr
	if ptr >= (len(r.buf) - 7) {
		r.refill()
		ptr = 0
	}
	x := uint64(0)
	r.ptr = ptr + 8
	for i := 0; i < 8; i++ {
		x += uint64(r.buf[ptr+i]) << (i << 3)
	}
	return x
}

// Refill a SHAKE256x4 instance.
func (r *shake256x4) refill() {
	var tmp [136]byte
	for i := 0; i < 4; i++ {
		r.state[i].Read(tmp[:])
		for j := 0; j < 17; j++ {
			u := (i << 3) + (j << 5)
			v := j << 3
			copy(r.buf[u:u+8], tmp[v:v+8])
		}
	}
	r.ptr = 0
}
