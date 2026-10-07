package totp

import (
	"encoding/base32"
	"testing"
	"time"
)

// RFC 6238 Appendix B test vectors.
func TestRFC6238(t *testing.T) {
	seeds := map[string]string{
		"SHA1":   "12345678901234567890",
		"SHA256": "12345678901234567890123456789012",
		"SHA512": "1234567890123456789012345678901234567890123456789012345678901234",
	}
	cases := []struct {
		t    int64
		algo string
		want string
	}{
		{59, "SHA1", "94287082"}, {59, "SHA256", "46119246"}, {59, "SHA512", "90693936"},
		{1111111109, "SHA1", "07081804"}, {1111111109, "SHA256", "68084774"}, {1111111109, "SHA512", "25091201"},
		{20000000000, "SHA1", "65353130"}, {20000000000, "SHA256", "77737706"}, {20000000000, "SHA512", "47863826"},
	}
	for _, c := range cases {
		sec := base32.StdEncoding.EncodeToString([]byte(seeds[c.algo]))
		p, err := Parse("otpauth://totp/x?secret=" + sec + "&digits=8&algorithm=" + c.algo)
		if err != nil {
			t.Fatal(err)
		}
		got, _ := p.Code(time.Unix(c.t, 0))
		if got != c.want {
			t.Errorf("%s @%d: got %s want %s", c.algo, c.t, got, c.want)
		}
	}
}

func TestPlainSecretAndRemaining(t *testing.T) {
	p, err := Parse("gezd gnbv gy3t qojq")
	if err != nil {
		t.Fatal(err)
	}
	code, rem := p.Code(time.Unix(65, 0))
	if len(code) != 6 || rem != 25 {
		t.Fatalf("code %q rem %d", code, rem)
	}
}

func TestSteam(t *testing.T) {
	p, err := Parse("steam://GEZDGNBVGY3TQOJQ")
	if err != nil {
		t.Fatal(err)
	}
	code, _ := p.Code(time.Unix(1000, 0))
	if len(code) != 5 {
		t.Fatalf("steam code %q", code)
	}
}

func TestInvalid(t *testing.T) {
	for _, s := range []string{"", "not base32!!", "otpauth://totp/x?secret=GEZD&algorithm=MD5"} {
		if _, err := Parse(s); err == nil {
			t.Errorf("expected error for %q", s)
		}
	}
}
