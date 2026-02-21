package fndsa

import (
	"encoding/binary"
	"fmt"
	sha3 "golang.org/x/crypto/sha3"
	"testing"
)

func TestMp31Core(t *testing.T) {
	sh := sha3.NewShake256()
	sh.Write([]byte("test_mp31"))
	for i := 0; i < 10; i++ {
		p := primes[i].p
		p0i := primes[i].p0i
		for j := 0; j < 65536; j++ {
			var buf [8]byte
			sh.Read(buf[:])
			a := binary.LittleEndian.Uint32(buf[:4]) % p
			b := binary.LittleEndian.Uint32(buf[4:]) % p
			c := mp_add(a, b, p)
			d := a + b
			if d >= p {
				d -= p
			}
			if c != d {
				t.Fatalf("ERR add: p=%d a=%d b=%d -> %d (expected: %d)\n",
					p, a, b, c, d)
			}
			c = mp_sub(a, b, p)
			d = a + p - b
			if d >= p {
				d -= p
			}
			if c != d {
				t.Fatalf("ERR sub: p=%d a=%d b=%d -> %d (expected: %d)\n",
					p, a, b, c, d)
			}
			c = mp_half(a, p)
			d = mp_add(c, c, p)
			if c >= p || d != a {
				t.Fatalf("ERR half: p=%d a=%d -> %d\n", p, a, c)
			}

			c = mp_mmul(a, b, p, p0i)
			d = uint32((uint64(a) * uint64(b)) % uint64(p))
			e := uint32((uint64(c) << 32) % uint64(p))
			if c >= p || e != d {
				t.Fatalf("ERR mmul: p=%d a=%d b=%d -> %d, %d (expected: %d)\n",
					p, a, b, c, e, d)
			}
			c = mp_div(a, b, p)
			d = uint32((uint64(c) * uint64(b)) % uint64(p))
			if b == 0 {
				d = a
			}
			if c >= p || d != a {
				t.Fatalf("ERR div: p=%d a=%d b=%d -> %d, %d\n",
					p, a, b, c, d)
			}
		}
	}
}

func TestMp31NTT(t *testing.T) {
	sh := sha3.NewShake256()
	t1 := make([]uint32, 1024)
	t2 := make([]uint32, 1024)
	t3 := make([]uint32, 1024)
	t4 := make([]uint32, 1024)
	t5 := make([]uint32, 1024)
	for m := 0; m < 10; m++ {
		p := primes[m].p
		p0i := primes[m].p0i
		r2 := primes[m].r2
		g := primes[m].g
		ig := primes[m].ig
		for logn := uint(1); logn <= 10; logn++ {
			n := 1 << logn
			for k := 0; k < 10; k++ {
				sh.Reset()
				var seed [2]uint8
				seed[0] = uint8(logn)
				seed[1] = uint8(k)
				sh.Write(seed[:])
				for j := 0; j < 2*n; j++ {
					var buf [4]uint8
					sh.Read(buf[:])
					x := binary.LittleEndian.Uint32(buf[:]) % p
					if j < n {
						t1[j] = x
					} else {
						t2[j-n] = x
					}
				}

				for i := 0; i < n; i++ {
					s := uint32(0)
					for j := 0; j <= i; j++ {
						s = mp_add(s, mp_mmul(t1[j], t2[i-j], p, p0i), p)
					}
					for j := i + 1; j < n; j++ {
						s = mp_sub(s, mp_mmul(t1[j], t2[i+n-j], p, p0i), p)
					}
					t3[i] = mp_mmul(s, r2, p, p0i)
				}

				mp_mkgmigm(logn, t4, t5, g, ig, p, p0i)
				mp_NTT(logn, t1, t4, p, p0i)
				mp_NTT(logn, t2, t4, p, p0i)
				for i := 0; i < n; i++ {
					t1[i] = mp_mmul(mp_mmul(t1[i], t2[i], p, p0i), r2, p, p0i)
				}
				mp_iNTT(logn, t1, t5, p, p0i)
				for i := 0; i < n; i++ {
					if t1[i] != t3[i] {
						t.Fatalf("ERR: %s vs %s\n", fmt.Sprint(t1[:n]), fmt.Sprint(t3[:n]))
					}
				}
			}
		}
	}
}
