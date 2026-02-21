// Package keys provides domain logic for key generation, public key
// derivation, message signing, and signature verification. Keys are
// represented as encoded strings (hex, base58, or raw binary); signatures
// are base64.
package keys

import (
	"crypto"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/mr-tron/base58"

	fndsa "example.com/pulse/pulse/pkg/crypto/falcon"
)

// Encoding represents the encoding format used for a key.
type Encoding uint8

const (
	Hex    Encoding = iota
	Base58 Encoding = iota
	Binary Encoding = iota
)

// Generate generates a new signing key and returns it encoded in the specified
// format.
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

// Decode decodes a key, returning its raw bytes and detected encoding.
// Hex is tried first, then base58. If neither matches, the input is treated
// as raw binary bytes.
func Decode(encoded string) ([]byte, Encoding, error) {
	if b, err := hex.DecodeString(encoded); err == nil {
		return b, Hex, nil
	}
	if b, err := base58.Decode(encoded); err == nil {
		return b, Base58, nil
	}
	return []byte(encoded), Binary, nil
}

// Encode encodes raw key bytes into the specified format.
func Encode(raw []byte, enc Encoding) string {
	switch enc {
	case Hex:
		return hex.EncodeToString(raw)
	case Base58:
		return base58.Encode(raw)
	default: // Binary
		return string(raw)
	}
}
