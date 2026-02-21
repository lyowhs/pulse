package fndsa

import (
	sha3 "golang.org/x/crypto/sha3"
	"testing"
)

func rndvect(logn uint, a []fxr, seed uint64) {
	sh := sha3.NewShake256()
	var buf [8]byte
	for i := 0; i < 8; i++ {
		buf[i] = byte(seed >> (i * 8))
	}
	sh.Write(buf[:])
	n := 1 << logn
	for i := 0; i < n; i++ {
		var tt [1]byte
		sh.Read(tt[:])
		a[i] = fxr_of(int32(int8(tt[0])))
	}
}

func TestVectFFT(t *testing.T) {
	for logn := uint(1); logn <= uint(10); logn++ {
		n := 1 << logn
		a := make([]fxr, n)
		b := make([]fxr, n)
		c := make([]fxr, n)
		//d := make([]fxr, n)
		for i := 0; i < 10; i++ {
			rndvect(logn, a,
				uint64(0)|(uint64(logn)<<8)|(uint64(i)<<12))
			rndvect(logn, b,
				uint64(1)|(uint64(logn)<<8)|(uint64(i)<<12))
			copy(c, a)
			vect_FFT(logn, c)
			vect_iFFT(logn, c)
			for j := 0; j < n; j++ {
				if fxr_round(a[j]) != fxr_round(c[j]) {
					t.Fatalf("ERR 1, j=%d: %d vs %d\n", j, int64(a[j]), int64(c[j]))
				}
			}
		}
	}
}
