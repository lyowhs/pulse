package fndsa

import (
	"fmt"
	"math"
	"testing"
)

func f64_to_string(x f64) string {
	v := f64_to_bits(x)
	return fmt.Sprintf("0x%016X (%v)", v, math.Float64frombits(v))
}

func rand_poly(logn uint, r *shake256x4, f []f64) {
	n := 1 << logn
	for i := 0; i < n; i++ {
		f[i] = f64_of(int64(r.next_u16()&0x3FF) - 512)
	}
}

func TestFFT(t *testing.T) {
	for logn := uint(1); logn <= 10; logn++ {
		n := 1 << logn
		r := newSHAKE256x4([]byte{byte(logn)})
		f := make([]f64, n)
		g := make([]f64, n)
		h := make([]f64, n)
		f0 := make([]f64, n>>1)
		f1 := make([]f64, n>>1)
		g0 := make([]f64, n>>1)
		g1 := make([]f64, n>>1)
		for ctr := 0; ctr < (1 << (15 - logn)); ctr++ {
			rand_poly(logn, r, f)
			copy(g, f)
			fpoly_FFT(logn, g)
			fpoly_iFFT(logn, g)
			for i := 0; i < n; i++ {
				if f64_rint(f[i]) != f64_rint(g[i]) {
					t.Fatalf("ERR1: i=%d n=%d: %s vs %s\n",
						i, n, f64_to_string(f[i]), f64_to_string(g[i]))
				}
			}

			if ctr < 5 {
				rand_poly(logn, r, g)
				for i := 0; i < n; i++ {
					h[i] = f64_ZERO
				}
				for i := 0; i < n; i++ {
					s := f64_ZERO
					for j := 0; j <= i; j++ {
						s = f64_add(s, f64_mul(f[j], g[i-j]))
					}
					for j := i + 1; j < n; j++ {
						s = f64_sub(s, f64_mul(f[j], g[i+n-j]))
					}
					h[i] = s
				}
				fpoly_FFT(logn, f)
				fpoly_FFT(logn, g)
				fpoly_mul_fft(logn, f, g)
				fpoly_iFFT(logn, f)
				for i := 0; i < n; i++ {
					if f64_rint(f[i]) != f64_rint(h[i]) {
						t.Fatalf("ERR2: i=%d n=%d: %s vs %s\n",
							i, n, f64_to_string(f[i]), f64_to_string(h[i]))
					}
				}
			}

			if logn >= 2 {
				rand_poly(logn, r, f)
				copy(h, f)
				fpoly_FFT(logn, f)
				fpoly_split_fft(logn, f0, f1, f)

				copy(g0, f0)
				copy(g1, f1)
				fpoly_iFFT(logn-1, g0)
				fpoly_iFFT(logn-1, g1)
				for i := 0; i < (n >> 1); i++ {
					if f64_rint(g0[i]) != f64_rint(h[2*i+0]) {
						t.Fatalf("ERR3: i=%d n=%d: %s vs %s\n", i, n,
							f64_to_string(g0[i]), f64_to_string(h[2*i+0]))
					}
					if f64_rint(g1[i]) != f64_rint(h[2*i+1]) {
						t.Fatalf("ERR4: i=%d n=%d: %s vs %s\n", i, n,
							f64_to_string(g1[i]), f64_to_string(h[2*i+1]))
					}
				}

				fpoly_merge_fft(logn, g, f0, f1)
				fpoly_iFFT(logn, g)
				for i := 0; i < n; i++ {
					if f64_rint(g[i]) != f64_rint(h[i]) {
						t.Fatalf("ERR5: i=%d n=%d: %s vs %s\n", i, n,
							f64_to_string(g[i]), f64_to_string(h[i]))
					}
				}
			}
		}
	}
}
