// Package keys provides domain logic for Falcon key generation, public key
// derivation, message signing, and signature verification. Keys are
// represented as encoded strings (hex or base58); signatures are base64.
package keys

import (
	"crypto"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/mr-tron/base58"

	fndsa "example.com/pulse/pulse/pkg/crypto/falcon"
)

// Encoding represents the string encoding format used for a key.
type Encoding uint8

const (
	Hex    Encoding = iota
	Base58 Encoding = iota
)

// Generate generates a new Falcon-512 signing key and returns it encoded in
// the specified format.
func Generate(enc Encoding) (string, error) {
	skey, _, err := fndsa.KeyGen(9, nil)
	if err != nil {
		return "", fmt.Errorf("key generation failed: %w", err)
	}
	return Encode(skey, enc), nil
}

// PublicKey derives the verifying (public) key from an encoded signing key.
// The output encoding matches the input encoding.
func PublicKey(encodedSigningKey string) (string, error) {
	skey, enc, err := Decode(encodedSigningKey)
	if err != nil {
		return "", fmt.Errorf("failed to decode signing key: %w", err)
	}
	vkey, err := fndsa.PublicKeyFromSecretKey(skey)
	if err != nil {
		return "", fmt.Errorf("failed to derive public key: %w", err)
	}
	return Encode(vkey, enc), nil
}

// Sign signs a message with the encoded signing key and returns a base64
// encoded signature.
func Sign(encodedSigningKey string, message []byte) (string, error) {
	skey, _, err := Decode(encodedSigningKey)
	if err != nil {
		return "", fmt.Errorf("failed to decode signing key: %w", err)
	}
	sig, err := fndsa.Sign(nil, skey, fndsa.DOMAIN_NONE, crypto.Hash(0), message)
	if err != nil {
		return "", fmt.Errorf("signing failed: %w", err)
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

// Verify verifies a base64 encoded signature against an encoded public key
// and message. Returns true if the signature is valid.
func Verify(encodedPublicKey string, message []byte, base64Sig string) (bool, error) {
	vkey, _, err := Decode(encodedPublicKey)
	if err != nil {
		return false, fmt.Errorf("failed to decode public key: %w", err)
	}
	sig, err := base64.StdEncoding.DecodeString(base64Sig)
	if err != nil {
		return false, fmt.Errorf("failed to decode signature: %w", err)
	}
	return fndsa.Verify(vkey, fndsa.DOMAIN_NONE, crypto.Hash(0), message, sig), nil
}

// Decode decodes a hex or base58 encoded key, returning the raw bytes and
// detected encoding. Hex is tried first.
func Decode(encoded string) ([]byte, Encoding, error) {
	if b, err := hex.DecodeString(encoded); err == nil {
		return b, Hex, nil
	}
	b, err := base58.Decode(encoded)
	if err != nil {
		return nil, 0, fmt.Errorf("key is neither valid hex nor valid base58")
	}
	return b, Base58, nil
}

// Encode encodes raw key bytes into the specified format.
func Encode(raw []byte, enc Encoding) string {
	if enc == Hex {
		return hex.EncodeToString(raw)
	}
	return base58.Encode(raw)
}
