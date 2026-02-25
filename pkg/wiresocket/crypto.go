package wiresocket

import (
	"crypto/rand"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

// ─── types ───────────────────────────────────────────────────────────────────

// Keypair is an X25519 Diffie-Hellman key pair.
type Keypair struct {
	Private [32]byte
	Public  [32]byte
}

// GenerateKeypair generates a new random X25519 key pair.
func GenerateKeypair() (Keypair, error) {
	var kp Keypair
	if _, err := rand.Read(kp.Private[:]); err != nil {
		return Keypair{}, err
	}
	// Clamp as per RFC 7748.
	kp.Private[0] &= 248
	kp.Private[31] = (kp.Private[31] & 127) | 64
	pub, err := curve25519.X25519(kp.Private[:], curve25519.Basepoint)
	if err != nil {
		return Keypair{}, err
	}
	copy(kp.Public[:], pub)
	return kp, nil
}

// ─── hash / MAC ──────────────────────────────────────────────────────────────

// hashFn returns BLAKE2s-256(data[0] || data[1] || ...).
func hashFn(data ...[]byte) [32]byte {
	h, _ := blake2s.New256(nil)
	for _, d := range data {
		h.Write(d)
	}
	var out [32]byte
	h.Sum(out[:0])
	return out
}

// mac returns keyed-BLAKE2s-256(key, data).
// key must be exactly 32 bytes.
func mac(key [32]byte, data []byte) [32]byte {
	h, _ := blake2s.New256(key[:])
	h.Write(data)
	var out [32]byte
	h.Sum(out[:0])
	return out
}

// macBytes is like mac but accepts a []byte key (truncated/zero-padded to 32).
func macBytes(key, data []byte) [32]byte {
	var k [32]byte
	copy(k[:], key)
	return mac(k, data)
}

// ─── KDF ─────────────────────────────────────────────────────────────────────

// kdf derives n×32 byte keys using HKDF-BLAKE2s.
//
// prk = BLAKE2s(key=ck, data=input)
// T1  = BLAKE2s(key=prk, data=0x01)
// T2  = BLAKE2s(key=prk, data=T1 || 0x02)
// ...
func kdf(ck [32]byte, input []byte, n int) [][32]byte {
	prk := mac(ck, input)
	out := make([][32]byte, n)
	var prev []byte
	for i := 0; i < n; i++ {
		in := append(prev, byte(i+1))
		out[i] = mac(prk, in)
		prev = out[i][:]
	}
	return out
}

func kdf2(ck [32]byte, input []byte) (ck1, t1 [32]byte) {
	r := kdf(ck, input, 2)
	return r[0], r[1]
}

func kdf3(ck [32]byte, input []byte) (ck1, t1, t2 [32]byte) {
	r := kdf(ck, input, 3)
	return r[0], r[1], r[2]
}

// ─── DH ──────────────────────────────────────────────────────────────────────

// dh computes X25519(priv, pub).
func dh(priv, pub [32]byte) ([32]byte, error) {
	out, err := curve25519.X25519(priv[:], pub[:])
	if err != nil {
		return [32]byte{}, err
	}
	var r [32]byte
	copy(r[:], out)
	return r, nil
}

// ─── AEAD ────────────────────────────────────────────────────────────────────

// encryptAEAD encrypts plaintext with ChaCha20-Poly1305.
// nonce encodes a 64-bit counter as: 4 zero bytes || counter (little-endian).
// The result is appended to dst.
func encryptAEAD(dst []byte, key [32]byte, counter uint64, aad, plain []byte) []byte {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		panic("wiresocket: chacha20poly1305.New: " + err.Error())
	}
	var nonce [12]byte
	binary.LittleEndian.PutUint64(nonce[4:], counter)
	return aead.Seal(dst, nonce[:], plain, aad)
}

// decryptAEAD decrypts and authenticates a ChaCha20-Poly1305 ciphertext.
func decryptAEAD(key [32]byte, counter uint64, aad, cipher []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err
	}
	var nonce [12]byte
	binary.LittleEndian.PutUint64(nonce[4:], counter)
	return aead.Open(nil, nonce[:], cipher, aad)
}

// randUint32 generates a cryptographically random 32-bit value.
func randUint32() (uint32, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b[:]), nil
}

// randBytes fills b with random bytes.
func randBytes(b []byte) error {
	_, err := rand.Read(b)
	return err
}

// zeroize overwrites b with zeros to clear sensitive material.
func zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

var errZeroDH = errors.New("wiresocket: DH produced all-zero result (low-order point)")

// dhSafe wraps dh and rejects the all-zero result.
func dhSafe(priv, pub [32]byte) ([32]byte, error) {
	r, err := dh(priv, pub)
	if err != nil {
		return [32]byte{}, err
	}
	var zero [32]byte
	if r == zero {
		return [32]byte{}, errZeroDH
	}
	return r, nil
}
