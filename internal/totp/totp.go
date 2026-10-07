// Package totp generates RFC 6238 codes from Bitwarden TOTP fields
// (plain base32 secrets, otpauth:// URIs and steam:// secrets).
package totp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Params describes a TOTP generator.
type Params struct {
	Secret    []byte
	Digits    int
	Period    int
	Algorithm string // SHA1, SHA256, SHA512
	Steam     bool
}

// Parse understands the formats Bitwarden stores in the TOTP field.
func Parse(s string) (*Params, error) {
	s = strings.TrimSpace(s)
	p := &Params{Digits: 6, Period: 30, Algorithm: "SHA1"}
	secret := s
	switch {
	case strings.HasPrefix(strings.ToLower(s), "otpauth://"):
		u, err := url.Parse(s)
		if err != nil {
			return nil, errors.New("invalid otpauth URI")
		}
		q := u.Query()
		secret = q.Get("secret")
		if d := q.Get("digits"); d != "" {
			n, err := strconv.Atoi(d)
			if err != nil || n < 1 || n > 10 {
				return nil, errors.New("invalid digits")
			}
			p.Digits = n
		}
		if per := q.Get("period"); per != "" {
			n, err := strconv.Atoi(per)
			if err != nil || n < 1 {
				return nil, errors.New("invalid period")
			}
			p.Period = n
		}
		if a := q.Get("algorithm"); a != "" {
			p.Algorithm = strings.ToUpper(a)
		}
		if strings.EqualFold(u.Host, "steam") {
			p.Steam, p.Digits = true, 5
		}
	case strings.HasPrefix(strings.ToLower(s), "steam://"):
		secret = s[len("steam://"):]
		p.Steam, p.Digits = true, 5
	}
	secret = strings.ToUpper(strings.NewReplacer(" ", "", "-", "", "=", "").Replace(secret))
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil || len(key) == 0 {
		return nil, errors.New("invalid base32 TOTP secret")
	}
	p.Secret = key
	switch p.Algorithm {
	case "SHA1", "SHA256", "SHA512":
	default:
		return nil, fmt.Errorf("unsupported TOTP algorithm %q", p.Algorithm)
	}
	return p, nil
}

const steamChars = "23456789BCDFGHJKMNPQRTVWXY"

// Code returns the code valid at t and the seconds remaining in its period.
func (p *Params) Code(t time.Time) (string, int) {
	counter := uint64(t.Unix()) / uint64(p.Period)
	remaining := p.Period - int(t.Unix()%int64(p.Period))
	var h func() hash.Hash
	switch p.Algorithm {
	case "SHA256":
		h = sha256.New
	case "SHA512":
		h = sha512.New
	default:
		h = sha1.New
	}
	m := hmac.New(h, p.Secret)
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	m.Write(buf[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	if p.Steam {
		out := make([]byte, 5)
		for i := range out {
			out[i] = steamChars[bin%uint32(len(steamChars))]
			bin /= uint32(len(steamChars))
		}
		return string(out), remaining
	}
	mod := uint64(1)
	for i := 0; i < p.Digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", p.Digits, uint64(bin)%mod), remaining
}
