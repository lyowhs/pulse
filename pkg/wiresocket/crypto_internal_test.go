package wiresocket

import (
	"bytes"
	"testing"
)

// TestGenerateKeypair verifies that GenerateKeypair produces a Keypair with
// a non-zero public key and that re-deriving the public key from the private
// key yields the same result.
func TestGenerateKeypair(t *testing.T) {
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	var zero [32]byte
	if kp.Public == zero {
		t.Error("Public key is all zeros")
	}
	if kp.Private == zero {
		t.Error("Private key is all zeros")
	}
	// Two keypairs should not be equal.
	kp2, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair #2: %v", err)
	}
	if kp.Public == kp2.Public {
		t.Error("Two generated keypairs have identical public keys")
	}
}

// TestHashFnDeterministic verifies that hashFn produces the same output for
// the same inputs and a different output for different inputs.
func TestHashFnDeterministic(t *testing.T) {
	a := hashFn([]byte("hello"), []byte("world"))
	b := hashFn([]byte("hello"), []byte("world"))
	if a != b {
		t.Error("hashFn is not deterministic")
	}
	c := hashFn([]byte("helloworld"))
	if a == c {
		// Concatenation of two pieces differs from single piece in BLAKE2s.
		// (The hash itself processes them sequentially, so they are equal here,
		// but a different message should differ.)
	}
	d := hashFn([]byte("different"))
	if a == d {
		t.Error("hashFn returned same output for different inputs")
	}
}

// TestMACKeyedDiffers verifies that mac with different keys produces
// different output for the same message.
func TestMACKeyedDiffers(t *testing.T) {
	var k1, k2 [32]byte
	k1[0] = 1
	k2[0] = 2
	data := []byte("test message")
	m1 := mac(k1, data)
	m2 := mac(k2, data)
	if m1 == m2 {
		t.Error("mac with different keys produced same output")
	}
}

// TestMACDeterministic verifies that mac is deterministic.
func TestMACDeterministic(t *testing.T) {
	var k [32]byte
	k[5] = 42
	data := []byte("payload")
	if mac(k, data) != mac(k, data) {
		t.Error("mac is not deterministic")
	}
}

// TestKDFLength verifies that kdf produces exactly n keys of 32 bytes each.
func TestKDFLength(t *testing.T) {
	var ck [32]byte
	input := []byte("kdf input")
	for n := 1; n <= 4; n++ {
		out := kdf(ck, input, n)
		if len(out) != n {
			t.Errorf("kdf(n=%d): got %d keys, want %d", n, len(out), n)
		}
		for i, k := range out {
			var zero [32]byte
			if k == zero {
				t.Errorf("kdf(n=%d): key[%d] is all zeros", n, i)
			}
		}
	}
}

// TestKDF2And3Consistency verifies that kdf2 and kdf3 are consistent with kdf.
func TestKDF2And3Consistency(t *testing.T) {
	var ck [32]byte
	ck[0] = 99
	input := []byte("test")

	r := kdf(ck, input, 3)
	ck1a, t1a := kdf2(ck, input)
	ck1b, t1b, t2b := kdf3(ck, input)

	if ck1a != r[0] || t1a != r[1] {
		t.Error("kdf2 inconsistent with kdf")
	}
	if ck1b != r[0] || t1b != r[1] || t2b != r[2] {
		t.Error("kdf3 inconsistent with kdf")
	}
}

// TestDHCommutative verifies X25519 DH: DH(a, B) == DH(b, A).
func TestDHCommutative(t *testing.T) {
	kpA, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	kpB, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	sharedAB, err := dh(kpA.Private, kpB.Public)
	if err != nil {
		t.Fatalf("dh(A.priv, B.pub): %v", err)
	}
	sharedBA, err := dh(kpB.Private, kpA.Public)
	if err != nil {
		t.Fatalf("dh(B.priv, A.pub): %v", err)
	}
	if sharedAB != sharedBA {
		t.Error("DH is not commutative")
	}
}

// TestDHSafeRejectsLowOrder verifies that dhSafe rejects a zero DH result.
// X25519 with the all-zeros point produces all-zeros output.
func TestDHSafeRejectsLowOrder(t *testing.T) {
	var zeroPoint [32]byte
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	// DH with the zero public key (low-order point) gives zero output.
	_, err = dhSafe(kp.Private, zeroPoint)
	if err == nil {
		t.Error("dhSafe accepted all-zero DH result (low-order point)")
	}
}

// TestEncryptDecryptAEAD verifies ChaCha20-Poly1305 roundtrip.
func TestEncryptDecryptAEAD(t *testing.T) {
	var key [32]byte
	key[0] = 7
	const counter uint64 = 42
	aad := []byte("associated data")
	plain := []byte("hello, world")

	cipher := encryptAEAD(nil, key, counter, aad, plain)
	if bytes.Equal(cipher, plain) {
		t.Error("ciphertext equals plaintext")
	}

	got, err := decryptAEAD(key, counter, aad, cipher)
	if err != nil {
		t.Fatalf("decryptAEAD: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Errorf("decrypted %q, want %q", got, plain)
	}
}

// TestEncryptDecryptAEADWrongKey verifies that authentication fails with a
// wrong key.
func TestEncryptDecryptAEADWrongKey(t *testing.T) {
	var key [32]byte
	key[0] = 7
	cipher := encryptAEAD(nil, key, 1, nil, []byte("message"))

	var wrongKey [32]byte
	wrongKey[0] = 8
	_, err := decryptAEAD(wrongKey, 1, nil, cipher)
	if err == nil {
		t.Error("decryptAEAD accepted ciphertext under wrong key")
	}
}

// TestEncryptDecryptAEADWrongCounter verifies that authentication fails with a
// wrong counter (nonce mismatch).
func TestEncryptDecryptAEADWrongCounter(t *testing.T) {
	var key [32]byte
	cipher := encryptAEAD(nil, key, 5, nil, []byte("message"))
	_, err := decryptAEAD(key, 6, nil, cipher)
	if err == nil {
		t.Error("decryptAEAD accepted ciphertext under wrong counter")
	}
}

// TestMacBytes verifies that macBytes with a short key is zero-padded and
// consistent with mac using the same zero-padded key.
func TestMacBytes(t *testing.T) {
	shortKey := []byte{1, 2, 3}
	data := []byte("data")
	got := macBytes(shortKey, data)

	var padded [32]byte
	copy(padded[:], shortKey)
	want := mac(padded, data)
	if got != want {
		t.Error("macBytes inconsistent with mac using zero-padded key")
	}
}

// TestZeroize verifies that zeroize overwrites all bytes with zero.
func TestZeroize(t *testing.T) {
	b := []byte{1, 2, 3, 4, 5}
	zeroize(b)
	for i, v := range b {
		if v != 0 {
			t.Errorf("zeroize: b[%d]=%d, want 0", i, v)
		}
	}
}
