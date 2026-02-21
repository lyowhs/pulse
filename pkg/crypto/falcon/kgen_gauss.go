package fndsa

// (f,g) sampling (Gaussian distribution).

// q = 12289, n = 256 -> kmax = 24
var gauss_256 = []uint16{
	1, 3, 6, 11, 22, 40, 73, 129,
	222, 371, 602, 950, 1460, 2183, 3179, 4509,
	6231, 8395, 11032, 14150, 17726, 21703, 25995, 30487,
	35048, 39540, 43832, 47809, 51385, 54503, 57140, 59304,
	61026, 62356, 63352, 64075, 64585, 64933, 65164, 65313,
	65406, 65462, 65495, 65513, 65524, 65529, 65532, 65534,
}

// q = 12289, n = 512 -> kmax = 17
var gauss_512 = []uint16{
	1, 4, 11, 28, 65, 146, 308, 615,
	1164, 2083, 3535, 5692, 8706, 12669, 17574, 23285,
	29542, 35993, 42250, 47961, 52866, 56829, 59843, 62000,
	63452, 64371, 64920, 65227, 65389, 65470, 65507, 65524,
	65531, 65534,
}

// q = 12289, n = 1024 -> kmax = 12
var gauss_1024 = []uint16{
	2, 8, 28, 94, 280, 742, 1761, 3753,
	7197, 12472, 19623, 28206, 37329, 45912, 53063, 58338,
	61782, 63774, 64793, 65255, 65441, 65507, 65527, 65533,
}

// Sample f (or g) from the provided SHAKE256-based PRNG. This function
// ensures that the sampled polynomial has odd parity.
func sample_f(logn uint, pc *shake256prng, f []int8) {
	n := 1 << logn
	var tab []uint16
	zz := 1
	switch logn {
	case 9:
		tab = gauss_512
	case 10:
		tab = gauss_1024
	default:
		tab = gauss_256
		zz = 1 << (8 - logn)
	}
	tab_len := len(tab)
	kmax := uint32(tab_len>>1) << 16

	// We loop until we sample an odd-parity polynomial.
	for {
		parity := uint32(0)
		i := 0
		for i < n {
			// Sampling: we choose a random 16-bit value y. We then
			// start with -kmax, and add 1 for each table entry
			// which is lower than y.
			// For logn < 8, we use the table for degree 256 but add
			// multiple samples together.
			v := uint32(0)
			for t := 0; t < zz; t++ {
				y := uint32(pc.next_u16())
				v -= kmax
				for k := 0; k < tab_len; k++ {
					v -= (uint32(tab[k]) - y) & ^uint32(0xFFFF)
				}
			}
			s := int32(v) >> 16
			// If logn <= 4, then it may happen that s is not in [-127,+127];
			// we must skip these values.
			if s < -127 || s > +127 {
				continue
			}
			f[i] = int8(s)
			i++
			parity ^= v
		}

		// Parity is in bit 16. We exit the loop if it is 1.
		if ((parity >> 16) & 1) != 0 {
			break
		}
	}
}
