package fndsa

import (
	"encoding/binary"
	"fmt"
	sha3 "golang.org/x/crypto/sha3"
	"testing"
)

func TestMqAdd(t *testing.T) {
	for x := uint32(1); x <= q; x++ {
		for y := uint32(1); y <= q; y++ {
			z := mq_add(x, y)
			r := x + y
			if r > q {
				r -= q
			}
			if r != z {
				t.Fatalf("ERR mq_add: %d %d -> %d (exp: %d)\n", x, y, z, r)
			}
		}
	}
}

func TestMqSub(t *testing.T) {
	for x := uint32(1); x <= q; x++ {
		for y := uint32(1); y <= q; y++ {
			z := mq_sub(x, y)
			r := q + x - y
			if r > q {
				r -= q
			}
			if r != z {
				t.Fatalf("ERR mq_sub: %d %d -> %d (exp: %d)\n", x, y, z, r)
			}
		}
	}
}

func TestMqHalf(t *testing.T) {
	for x := uint32(1); x <= q; x++ {
		z := mq_half(x)
		r := x
		if (r & 1) != 0 {
			r += q
		}
		r >>= 1
		if r != z {
			t.Fatalf("ERR mq_half: %d -> %d (exp: %d)\n", x, z, r)
		}
	}
}

func TestMqMmul(t *testing.T) {
	for x := uint32(1); x <= q; x++ {
		for y := uint32(1); y <= q; y++ {
			z := mq_mmul(x, y)
			r := (x * y) % q
			r = 1 + ((r*11857 + (q - 1)) % q)
			if r != z {
				t.Fatalf("ERR mq_mmul: %d %d -> %d (exp: %d)\n", x, y, z, r)
			}
		}
	}
}

func TestMqDiv(t *testing.T) {
	// We don't test all values of x because that's somewhat expensive.
	for x := uint32(1); x <= 100; x++ {
		for y := uint32(1); y < q; y++ {
			z := mq_div(x, y)
			w := mq_mmul(r2, mq_mmul(z, y))
			if w != x {
				t.Fatalf("ERR mq_div: %d %d -> %d\n", x, y, z)
			}
		}
	}
}

func TestMqPolyNTT(t *testing.T) {
	sh := sha3.NewShake256()
	for logn := uint(1); logn <= 10; logn++ {
		n := 1 << logn
		t1 := make([]uint16, n)
		t2 := make([]uint16, n)
		t3 := make([]uint16, n)
		for k := 0; k < 10; k++ {
			sh.Reset()
			var seed [2]uint8
			seed[0] = uint8(logn)
			seed[1] = uint8(k)
			sh.Write(seed[:])
			for j := 0; j < 2*n; j++ {
				var buf [4]uint8
				sh.Read(buf[:])
				x := uint16(binary.LittleEndian.Uint32(buf[:]) % q)
				if j < n {
					t1[j] = x
				} else {
					t2[j-n] = x
				}
			}

			for i := 0; i < n; i++ {
				s := uint64(0)
				for j := 0; j <= i; j++ {
					s += uint64(uint32(t1[j]) * uint32(t2[i-j]))
				}
				for j := i + 1; j < n; j++ {
					s += uint64((q * q) - uint32(t1[j])*uint32(t2[i+n-j]))
				}
				t3[i] = uint16(s % uint64(q))
			}

			mqpoly_ext_to_int(logn, t1)
			mqpoly_int_to_ntt(logn, t1)
			mqpoly_ext_to_int(logn, t2)
			mqpoly_int_to_ntt(logn, t2)
			mqpoly_mul_ntt(logn, t1, t2)
			mqpoly_ntt_to_int(logn, t1)
			mqpoly_int_to_ext(logn, t1)
			for i := 0; i < n; i++ {
				if t1[i] != t3[i] {
					t.Fatalf("ERR: %s vs %s\n", fmt.Sprint(t1), fmt.Sprint(t3))
				}
			}
		}
	}
}
