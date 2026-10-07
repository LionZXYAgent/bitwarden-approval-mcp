package server

import "testing"

func TestPolicyAllowDeny(t *testing.T) {
	cases := []struct {
		name        string
		allow, deny []string
		item        string
		want        bool
	}{
		{"default allow", nil, nil, "GitHub", true},
		{"allowlist match", []string{"git*"}, nil, "GitHub", true},
		{"allowlist miss", []string{"git*"}, nil, "AWS", false},
		{"deny wins", []string{"*"}, []string{"prod*"}, "prod-db", false},
		{"deny miss allow hit", []string{"*"}, []string{"prod*"}, "dev-db", true},
		{"substring allow", []string{"hub"}, nil, "GitHub", true},
		{"exact id", []string{"abc-123"}, nil, "", true},
	}
	for _, c := range cases {
		p := newPolicy(c.allow, c.deny)
		id := ""
		if c.name == "exact id" {
			id = "abc-123"
		}
		if got := p.allowed(c.item, id); got != c.want {
			t.Errorf("%s: allowed(%q)=%v want %v", c.name, c.item, got, c.want)
		}
	}
}
