package vdf

import (
	"crypto/rand"
	"crypto/rsa"
	"math/big"
)

// DefaultModulus returns the RSA-2048 challenge number — a 2048-bit RSA
// modulus whose factorisation has never been publicly found. It is suitable
// as a production VDF modulus without a trusted setup ceremony.
func DefaultModulus() *big.Int {
	n, _ := new(big.Int).SetString(rsa2048, 10)
	return n
}

// GenerateModulus generates a fresh RSA modulus of the given bit size.
//
// WARNING: the caller implicitly knows the prime factors of the returned
// modulus, which means the delay guarantee does not hold against them. For
// production use, prefer [DefaultModulus] or a modulus produced by a trusted
// multi-party setup where no single party retains the factorisation.
func GenerateModulus(bits int) (*big.Int, error) {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	return key.N, nil
}

// rsa2048 is the RSA-2048 challenge number (decimal). Its factorisation is
// unknown. Source: https://en.wikipedia.org/wiki/RSA_numbers#RSA-2048
const rsa2048 = "25195908475657893494027183240048398571429282126204032027777137836043662020707595556264018525880784406918290641249515082189298559149176184502808489120072844992687392807287776735971418347270261896375014971824691165077613379859095700097330459748808428401797429100642458691817195118746121515172654632282216869987549182422433637259085141865462043576798423387184774447920739934236584823824281198163815010674810451660377306056201619676256133844143603833904414952634432190114657544454178424020924616515723350778707749817125772467962926386356373289912154831438167899885040445364023527381951378636564391212010397122822120720357"
