package server

import "testing"

func TestRateLimiter(t *testing.T) {
	r := newRateLimiter(3)
	for i := 0; i < 3; i++ {
		if !r.allow("a") {
			t.Fatalf("hit %d should be allowed", i)
		}
	}
	if r.allow("a") {
		t.Fatal("4th hit should be blocked")
	}
	if !r.allow("b") {
		t.Fatal("different key should be allowed")
	}
	if !newRateLimiter(0).allow("x") {
		t.Fatal("zero limit disables limiting")
	}
}
