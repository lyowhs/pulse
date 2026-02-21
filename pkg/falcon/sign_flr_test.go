package fndsa

import (
	"math"
	"testing"
)

func eqf(t *testing.T, x f64, rx float64) {
	v := f64_to_bits(x)
	rv := math.Float64bits(rx)
	if v != rv {
		t.Fatalf("ERR: 0x%016X (%.20f) vs 0x%016X (%.20f)\n",
			v, math.Float64frombits(v), rv, rx)
	}
}

func rand_fp(r *shake256x4) f64 {
	m := r.next_u64()
	e := (((m >> 52) & 0x7FF) % 161) + 943
	m = (m & 0x800FFFFFFFFFFFFF) | (e << 52)
	return f64_from_bits(m)
}

func TestFlrNative(t *testing.T) {
	// We test the emulated floating-point code against the native support,
	// which is supposed to adhere to strict IEEE 754, at least as long
	// as we enforce rounding where appropriate (i.e. we prevent contraction
	// of expressions across statements).
	eqf(t, f64_ZERO, 0.0)
	z := 0.0
	nz := float64(-z)
	eqf(t, f64_half(f64_ZERO), z)
	eqf(t, f64_half(f64_NZERO), nz)
	eqf(t, f64_add(f64_ZERO, f64_ZERO), float64(z+z))
	eqf(t, f64_add(f64_ZERO, f64_NZERO), float64(z+nz))
	eqf(t, f64_add(f64_NZERO, f64_ZERO), float64(nz+z))
	eqf(t, f64_add(f64_NZERO, f64_NZERO), float64(nz+nz))
	eqf(t, f64_sub(f64_ZERO, f64_ZERO), float64(z-z))
	eqf(t, f64_sub(f64_ZERO, f64_NZERO), float64(z-nz))
	eqf(t, f64_sub(f64_NZERO, f64_ZERO), float64(nz-z))
	eqf(t, f64_sub(f64_NZERO, f64_NZERO), float64(nz-nz))

	for e := -60; e <= +60; e++ {
		for i := -5; i <= +5; i++ {
			a := f64_of((int64(1) << 53) + int64(i))
			ax := float64(9007199254740992.0 + float64(i))
			eqf(t, a, ax)
			for j := -5; j <= 5; j++ {
				b := f64_scaled((int64(1)<<53)+int64(i), int32(e))
				bx := math.Ldexp(float64(9007199254740992.0+float64(i)), e)
				bx = float64(bx)
				eqf(t, b, bx)
				eqf(t, f64_add(a, b), float64(ax+bx))
				a = f64_neg(a)
				eqf(t, f64_add(a, b), float64(bx-ax))
				b = f64_neg(b)
				eqf(t, f64_add(a, b), float64(-bx-ax))
				a = f64_neg(a)
				eqf(t, f64_add(a, b), float64(ax-bx))
			}
		}
	}

	r := newSHAKE256x4([]byte("fpemu"))
	for ctr := 1; ctr <= 65536; ctr++ {
		j := int64(r.next_u64()) >> (ctr & 63)
		if j == -9223372036854775808 {
			t.Fatalf("PRNG yielded -2^63")
		}
		a := f64_of(j)
		ax := float64(j)
		eqf(t, a, ax)

		sc := (int32(r.next_u16()) & 0xFF) - 128
		eqf(t, f64_scaled(j, sc), float64(math.Ldexp(float64(j), int(sc))))

		j = int64(r.next_u64())
		a = f64_scaled(j, -33)
		ax = float64(math.Ldexp(float64(j), -33))
		if f64_rint(a) != int32(math.RoundToEven(ax)) {
			t.Fatalf("ERR rint 0x%016X (%.20f) -> %d (exp: %d)\n",
				f64_to_bits(a), float64(math.Float64frombits(f64_to_bits(a))),
				f64_rint(a), int32(math.RoundToEven(ax)))
		}
		if f64_trunc(a) != int32(math.Trunc(ax)) {
			t.Fatalf("ERR trunc 0x%016X (%.20f) -> %d (exp: %d)\n",
				f64_to_bits(a), float64(math.Float64frombits(f64_to_bits(a))),
				f64_trunc(a), int32(math.Trunc(ax)))
		}

		js := j >> 63
		ju := (j ^ js) - js
		a = f64_scaled(ju, -63)
		ax = float64(math.Ldexp(float64(ju), -63))
		if f64_mtwop63(a) != uint64(math.Trunc(ax*9223372036854775808.0)) {
			t.Fatalf("ERR mtwop63 0x%016X (%.20f) -> %d (exp: %d)\n",
				f64_to_bits(a), float64(math.Float64frombits(f64_to_bits(a))),
				f64_mtwop63(a), uint64(math.Trunc(ax*9223372036854775808.0)))
		}

		a = f64_scaled(j, -52)
		ax = float64(math.Ldexp(float64(j), -52))
		if f64_floor(a) != int32(math.Floor(ax)) {
			t.Fatalf("ERR floor 0x%016X (%.20f) -> %d (exp: %d)\n",
				f64_to_bits(a), float64(math.Float64frombits(f64_to_bits(a))),
				f64_floor(a), int32(math.Floor(ax)))
		}

		a = rand_fp(r)
		b := rand_fp(r)
		ax = float64(math.Float64frombits(f64_to_bits(a)))
		bx := float64(math.Float64frombits(f64_to_bits(b)))

		eqf(t, f64_add(a, b), float64(ax+bx))
		eqf(t, f64_add(b, a), float64(bx+ax))
		eqf(t, f64_add(a, f64_ZERO), float64(ax+z))
		eqf(t, f64_add(f64_ZERO, a), float64(z+ax))
		eqf(t, f64_add(a, f64_neg(a)), float64(ax+float64(-ax)))
		eqf(t, f64_add(f64_neg(a), a), float64(float64(-ax)+ax))

		eqf(t, f64_sub(a, b), float64(ax-bx))
		eqf(t, f64_sub(b, a), float64(bx-ax))
		eqf(t, f64_sub(a, f64_ZERO), float64(ax-z))
		eqf(t, f64_sub(f64_ZERO, a), float64(z-ax))
		eqf(t, f64_sub(a, a), float64(ax-ax))

		eqf(t, f64_neg(a), float64(-ax))
		eqf(t, f64_half(a), float64(ax*0.5))
		eqf(t, f64_double(a), float64(ax*2.0))

		eqf(t, f64_mul(a, b), float64(ax*bx))
		eqf(t, f64_mul(b, a), float64(bx*ax))
		eqf(t, f64_mul(a, f64_ZERO), float64(ax*0.0))
		eqf(t, f64_mul(f64_ZERO, a), float64(0.0*ax))

		eqf(t, f64_div(a, b), float64(ax/bx))
		a = f64_abs(a)
		ax = float64(math.Abs(ax))
		eqf(t, a, ax)
		eqf(t, f64_sqrt(a), float64(math.Sqrt(ax)))
	}
}
