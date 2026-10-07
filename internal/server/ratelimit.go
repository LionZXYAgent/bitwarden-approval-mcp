package server

import (
	"sync"
	"time"
)

// rateLimiter is a simple per-key sliding-window counter.
type rateLimiter struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	hits   map[string][]time.Time
}

func newRateLimiter(perMinute int) *rateLimiter {
	return &rateLimiter{limit: perMinute, window: time.Minute, hits: map[string][]time.Time{}}
}

// allow records a hit and reports whether key is within its limit.
func (r *rateLimiter) allow(key string) bool {
	if r.limit <= 0 {
		return true
	}
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	cut := now.Add(-r.window)
	keep := r.hits[key][:0]
	for _, t := range r.hits[key] {
		if t.After(cut) {
			keep = append(keep, t)
		}
	}
	if len(keep) >= r.limit {
		r.hits[key] = keep
		return false
	}
	r.hits[key] = append(keep, now)
	return true
}
