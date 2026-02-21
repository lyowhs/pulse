package keys

import (
	"strings"
	"testing"
)

func TestGenerateAndPublicKey(t *testing.T) {
	for _, enc := range []Encoding{Hex, Base58} {
		sk, err := Generate(enc)
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		pk, err := PublicKey(sk)
		if err != nil {
			t.Fatalf("PublicKey: %v", err)
		}
		if sk == "" || pk == "" {
			t.Fatal("expected non-empty keys")
		}
	}
}

func TestPublicKeyPreservesEncoding(t *testing.T) {
	skHex, _ := Generate(Hex)
	pkHex, _ := PublicKey(skHex)
	_, enc, err := Decode(pkHex)
	if err != nil {
		t.Fatalf("expected hex public key, got: %s", pkHex)
	}
	if enc != Hex {
		t.Fatal("expected hex encoding to be preserved")
	}

	skB58, _ := Generate(Base58)
	pkB58, _ := PublicKey(skB58)
	_, enc, _ = Decode(pkB58)
	if enc != Base58 {
		t.Fatal("expected base58 encoding to be preserved")
	}
}

func TestSignAndVerify(t *testing.T) {
	sk, _ := Generate(Base58)
	pk, _ := PublicKey(sk)
	msg := []byte("Hello World!")

	sig, err := Sign(sk, msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	ok, err := Verify(pk, msg, sig)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Fatal("expected valid signature")
	}
}

func TestVerifyRejectsWrongMessage(t *testing.T) {
	sk, _ := Generate(Base58)
	pk, _ := PublicKey(sk)
	sig, _ := Sign(sk, []byte("correct"))

	ok, err := Verify(pk, []byte("wrong"), sig)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if ok {
		t.Fatal("expected invalid signature for wrong message")
	}
}

func TestVerifyRejectsTamperedSignature(t *testing.T) {
	sk, _ := Generate(Base58)
	pk, _ := PublicKey(sk)
	sig, _ := Sign(sk, []byte("hello"))

	tampered := strings.ToUpper(sig)
	ok, _ := Verify(pk, []byte("hello"), tampered)
	if ok {
		t.Fatal("expected invalid signature for tampered input")
	}
}

func TestDecodeHex(t *testing.T) {
	sk, _ := Generate(Hex)
	raw, enc, err := Decode(sk)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if enc != Hex {
		t.Fatal("expected Hex encoding")
	}
	if len(raw) == 0 {
		t.Fatal("expected non-empty raw bytes")
	}
}

func TestDecodeBase58(t *testing.T) {
	sk, _ := Generate(Base58)
	raw, enc, err := Decode(sk)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if enc != Base58 {
		t.Fatal("expected Base58 encoding")
	}
	if len(raw) == 0 {
		t.Fatal("expected non-empty raw bytes")
	}
}

func TestDecodeInvalid(t *testing.T) {
	_, _, err := Decode("not-valid-!!!")
	if err == nil {
		t.Fatal("expected error for invalid input")
	}
}
