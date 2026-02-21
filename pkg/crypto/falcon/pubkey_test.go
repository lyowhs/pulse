package fndsa

import (
	"bytes"
	"testing"
)

func TestPublicKeyFromSecretKey(t *testing.T) {
	skey, vkey, err := KeyGen(9, nil)
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}

	derived, err := PublicKeyFromSecretKey(skey)
	if err != nil {
		t.Fatalf("PublicKeyFromSecretKey failed: %v", err)
	}

	if !bytes.Equal(vkey, derived) {
		t.Fatal("derived public key does not match KeyGen output")
	}
}
