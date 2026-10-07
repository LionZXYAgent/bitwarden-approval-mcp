// Package vault implements a minimal, read-only Bitwarden client: login,
// sync, and client-side decryption of vault items. It talks directly to the
// Bitwarden (or Vaultwarden) HTTP API so no Node.js `bw` CLI is required.
package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

// KDF types as used by the Bitwarden API.
const (
	KDFPBKDF2   = 0
	KDFArgon2id = 1
)

// KDFParams describes how the master key is derived from the master password.
type KDFParams struct {
	Type        int  `json:"kdf"`
	Iterations  int  `json:"kdfIterations"`
	Memory      *int `json:"kdfMemory"`      // MiB, Argon2id only
	Parallelism *int `json:"kdfParallelism"` // Argon2id only
}

// SymKey is a 64-byte AES-256-CBC + HMAC-SHA256 key pair.
type SymKey struct {
	Enc []byte
	Mac []byte
}

// Wipe overwrites the key material. Go's GC may still hold copies; this is
// best-effort hygiene, not a guarantee.
func (k *SymKey) Wipe() {
	if k == nil {
		return
	}
	wipe(k.Enc)
	wipe(k.Mac)
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// DeriveMasterKey derives the 32-byte master key.
func DeriveMasterKey(password []byte, email string, kdf KDFParams) ([]byte, error) {
	salt := strings.ToLower(strings.TrimSpace(email))
	switch kdf.Type {
	case KDFPBKDF2:
		if kdf.Iterations < 5000 {
			return nil, fmt.Errorf("refusing PBKDF2 with %d iterations", kdf.Iterations)
		}
		return pbkdf2.Key(sha256.New, string(password), []byte(salt), kdf.Iterations, 32)
	case KDFArgon2id:
		if kdf.Memory == nil || kdf.Parallelism == nil {
			return nil, errors.New("argon2id parameters missing")
		}
		s := sha256.Sum256([]byte(salt))
		return argon2.IDKey(password, s[:], uint32(kdf.Iterations), uint32(*kdf.Memory)*1024, uint8(*kdf.Parallelism), 32), nil
	default:
		return nil, fmt.Errorf("unsupported KDF type %d", kdf.Type)
	}
}

// MasterPasswordHash is the server-side authentication hash (base64).
func MasterPasswordHash(masterKey, password []byte) string {
	h, _ := pbkdf2.Key(sha256.New, string(masterKey), password, 1, 32)
	return base64.StdEncoding.EncodeToString(h)
}

// StretchMasterKey expands the master key into an enc/mac pair via HKDF-Expand.
func StretchMasterKey(masterKey []byte) (*SymKey, error) {
	enc := make([]byte, 32)
	mac := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.Expand(sha256.New, masterKey, []byte("enc")), enc); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(hkdf.Expand(sha256.New, masterKey, []byte("mac")), mac); err != nil {
		return nil, err
	}
	return &SymKey{Enc: enc, Mac: mac}, nil
}

// SymKeyFromBytes splits a 64-byte key (32 bytes enc || 32 bytes mac).
func SymKeyFromBytes(b []byte) (*SymKey, error) {
	if len(b) != 64 {
		return nil, fmt.Errorf("unexpected symmetric key length %d", len(b))
	}
	k := &SymKey{Enc: make([]byte, 32), Mac: make([]byte, 32)}
	copy(k.Enc, b[:32])
	copy(k.Mac, b[32:])
	return k, nil
}

// Bytes returns enc||mac.
func (k *SymKey) Bytes() []byte {
	out := make([]byte, 0, 64)
	out = append(out, k.Enc...)
	return append(out, k.Mac...)
}

// EncString is a parsed Bitwarden "type.iv|data|mac" string.
type EncString struct {
	Type int
	IV   []byte
	Data []byte
	Mac  []byte
}

// ErrUnsupportedEncType is returned for encryption types this client does not implement.
var ErrUnsupportedEncType = errors.New("unsupported encryption type")

// ParseEncString parses a Bitwarden encrypted string.
func ParseEncString(s string) (*EncString, error) {
	dot := strings.IndexByte(s, '.')
	if dot < 1 {
		return nil, errors.New("malformed encrypted string")
	}
	t, err := strconv.Atoi(s[:dot])
	if err != nil {
		return nil, errors.New("malformed encrypted string type")
	}
	parts := strings.Split(s[dot+1:], "|")
	dec := func(p string) ([]byte, error) { return base64.StdEncoding.DecodeString(p) }
	es := &EncString{Type: t}
	switch t {
	case 0, 1, 2:
		want := 3
		if t == 0 {
			want = 2
		}
		if len(parts) != want {
			return nil, errors.New("malformed encrypted string parts")
		}
		if es.IV, err = dec(parts[0]); err != nil {
			return nil, err
		}
		if es.Data, err = dec(parts[1]); err != nil {
			return nil, err
		}
		if want == 3 {
			if es.Mac, err = dec(parts[2]); err != nil {
				return nil, err
			}
		}
	case 3, 4, 5, 6:
		if es.Data, err = dec(parts[0]); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("%w %d", ErrUnsupportedEncType, t)
	}
	return es, nil
}

// String serialises the EncString.
func (e *EncString) String() string {
	b := base64.StdEncoding.EncodeToString
	switch e.Type {
	case 2:
		return fmt.Sprintf("2.%s|%s|%s", b(e.IV), b(e.Data), b(e.Mac))
	case 4:
		return "4." + b(e.Data)
	}
	return ""
}

// DecryptSym decrypts a type 2 (AES-CBC-256 + HMAC-SHA256) EncString.
func DecryptSym(s string, key *SymKey) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	es, err := ParseEncString(s)
	if err != nil {
		return nil, err
	}
	if es.Type != 2 {
		return nil, fmt.Errorf("%w %d for symmetric decryption", ErrUnsupportedEncType, es.Type)
	}
	m := hmac.New(sha256.New, key.Mac)
	m.Write(es.IV)
	m.Write(es.Data)
	if !hmac.Equal(m.Sum(nil), es.Mac) {
		return nil, errors.New("MAC mismatch (wrong key or corrupted data)")
	}
	if len(es.Data) == 0 || len(es.Data)%aes.BlockSize != 0 || len(es.IV) != aes.BlockSize {
		return nil, errors.New("invalid ciphertext length")
	}
	block, err := aes.NewCipher(key.Enc)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(es.Data))
	cipher.NewCBCDecrypter(block, es.IV).CryptBlocks(out, es.Data)
	return pkcs7Unpad(out)
}

// DecryptSymString decrypts to a string.
func DecryptSymString(s string, key *SymKey) (string, error) {
	b, err := DecryptSym(s, key)
	return string(b), err
}

// EncryptSym produces a type 2 EncString (used by tests and seeding tools).
func EncryptSym(plain []byte, key *SymKey) (string, error) {
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key.Enc)
	if err != nil {
		return "", err
	}
	padded := pkcs7Pad(plain)
	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)
	m := hmac.New(sha256.New, key.Mac)
	m.Write(iv)
	m.Write(ct)
	return (&EncString{Type: 2, IV: iv, Data: ct, Mac: m.Sum(nil)}).String(), nil
}

// DecryptRSA decrypts a type 4 (RSA-2048-OAEP-SHA1) or type 3 (OAEP-SHA256) EncString.
func DecryptRSA(s string, priv *rsa.PrivateKey) ([]byte, error) {
	es, err := ParseEncString(s)
	if err != nil {
		return nil, err
	}
	switch es.Type {
	case 4, 6:
		return rsa.DecryptOAEP(sha1.New(), nil, priv, es.Data, nil)
	case 3, 5:
		return rsa.DecryptOAEP(sha256.New(), nil, priv, es.Data, nil)
	}
	return nil, fmt.Errorf("%w %d for asymmetric decryption", ErrUnsupportedEncType, es.Type)
}

// EncryptRSA produces a type 4 EncString (tests/seeding).
func EncryptRSA(plain []byte, pub *rsa.PublicKey) (string, error) {
	ct, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, pub, plain, nil)
	if err != nil {
		return "", err
	}
	return (&EncString{Type: 4, Data: ct}).String(), nil
}

// ParsePrivateKey parses a PKCS#8 DER RSA private key.
func ParsePrivateKey(der []byte) (*rsa.PrivateKey, error) {
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not RSA")
	}
	return rk, nil
}

func pkcs7Pad(b []byte) []byte {
	n := aes.BlockSize - len(b)%aes.BlockSize
	out := make([]byte, len(b)+n)
	copy(out, b)
	for i := len(b); i < len(out); i++ {
		out[i] = byte(n)
	}
	return out
}

func pkcs7Unpad(b []byte) ([]byte, error) {
	if len(b) == 0 {
		return nil, errors.New("empty plaintext")
	}
	n := int(b[len(b)-1])
	if n == 0 || n > aes.BlockSize || n > len(b) {
		return nil, errors.New("bad padding")
	}
	for _, c := range b[len(b)-n:] {
		if int(c) != n {
			return nil, errors.New("bad padding")
		}
	}
	return b[:len(b)-n], nil
}
