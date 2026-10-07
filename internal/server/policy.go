package server

import (
	"path"
	"strings"
)

// policy decides whether an item may be requested at all.
type policy struct {
	allow []string
	deny  []string
}

func newPolicy(allow, deny []string) policy { return policy{allow: allow, deny: deny} }

// match reports whether any pattern matches the item name or id
// (case-insensitive, glob via path.Match, plus substring fallback).
func match(patterns []string, name, id string) bool {
	ln, li := strings.ToLower(name), strings.ToLower(id)
	for _, p := range patterns {
		lp := strings.ToLower(p)
		if lp == li || lp == ln {
			return true
		}
		if ok, _ := path.Match(lp, ln); ok {
			return true
		}
		if strings.Contains(lp, "*") {
			continue
		}
		if strings.Contains(ln, lp) {
			return true
		}
	}
	return false
}

// allowed applies deny-then-allow precedence.
func (p policy) allowed(name, id string) bool {
	if len(p.deny) > 0 && match(p.deny, name, id) {
		return false
	}
	if len(p.allow) > 0 {
		return match(p.allow, name, id)
	}
	return true
}
