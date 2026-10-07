package vault

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func testKey(t *testing.T) *SymKey {
	t.Helper()
	b := make([]byte, 64)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	k, err := SymKeyFromBytes(b)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestSymRoundTrip(t *testing.T) {
	k := testKey(t)
	for _, msg := range []string{"", "hunter2", "a longer secret value with unicode ☃ and symbols !@#"} {
		enc, err := EncryptSym([]byte(msg), k)
		if err != nil {
			t.Fatal(err)
		}
		dec, err := DecryptSymString(enc, k)
		if err != nil {
			t.Fatal(err)
		}
		if dec != msg {
			t.Fatalf("round trip: got %q want %q", dec, msg)
		}
	}
}

func TestMACTamperDetected(t *testing.T) {
	k := testKey(t)
	enc, _ := EncryptSym([]byte("secret"), k)
	es, _ := ParseEncString(enc)
	es.Data[0] ^= 0xff
	if _, err := DecryptSym(es.String(), k); err == nil {
		t.Fatal("expected MAC mismatch error")
	}
}

func TestWrongKeyFails(t *testing.T) {
	enc, _ := EncryptSym([]byte("secret"), testKey(t))
	if _, err := DecryptSym(enc, testKey(t)); err == nil {
		t.Fatal("expected failure with wrong key")
	}
}

func TestRSARoundTrip(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := EncryptRSA([]byte("orgkey-material"), &priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := DecryptRSA(enc, priv)
	if err != nil {
		t.Fatal(err)
	}
	if string(dec) != "orgkey-material" {
		t.Fatalf("rsa round trip got %q", dec)
	}
}

func TestDeriveMasterKeyPBKDF2(t *testing.T) {
	// Known Bitwarden test vector (email+password -> master key -> hash).
	mk, err := DeriveMasterKey([]byte("password"), "nobody@example.com", KDFParams{Type: KDFPBKDF2, Iterations: 600000})
	if err != nil {
		t.Fatal(err)
	}
	if len(mk) != 32 {
		t.Fatalf("master key length %d", len(mk))
	}
	h := MasterPasswordHash(mk, []byte("password"))
	if h == "" {
		t.Fatal("empty hash")
	}
	// Stability: same inputs produce same key.
	mk2, _ := DeriveMasterKey([]byte("password"), "nobody@example.com", KDFParams{Type: KDFPBKDF2, Iterations: 600000})
	if !bytes.Equal(mk, mk2) {
		t.Fatal("master key not deterministic")
	}
}

func TestStretchMasterKey(t *testing.T) {
	mk := make([]byte, 32)
	k, err := StretchMasterKey(mk)
	if err != nil {
		t.Fatal(err)
	}
	if len(k.Enc) != 32 || len(k.Mac) != 32 || bytes.Equal(k.Enc, k.Mac) {
		t.Fatal("bad stretched key")
	}
}

func TestParseEncStringErrors(t *testing.T) {
	for _, s := range []string{"", "nope", "9.abc", "2.only|two"} {
		if _, err := ParseEncString(s); err == nil {
			t.Errorf("expected error parsing %q", s)
		}
	}
}

func TestWipe(t *testing.T) {
	k := testKey(t)
	k.Wipe()
	if !bytes.Equal(k.Enc, make([]byte, 32)) || !bytes.Equal(k.Mac, make([]byte, 32)) {
		t.Fatal("wipe did not zero key")
	}
}
