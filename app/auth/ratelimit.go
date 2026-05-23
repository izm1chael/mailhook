package auth

import (
	"sync"
	"time"
)

// LoginRateLimiter enforces per-IP login attempt limits.
// Policy: 5 attempts per 5 minutes → 15-minute lockout.
type LoginRateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	count       int
	windowStart time.Time
	lockedUntil time.Time
}

// NewLoginRateLimiter creates a rate limiter.
func NewLoginRateLimiter() *LoginRateLimiter {
	return &LoginRateLimiter{buckets: make(map[string]*bucket)}
}

// Allow returns (true, 0) if the IP is allowed to attempt login.
// Returns (false, retryAfter) if the IP is locked out.
func (l *LoginRateLimiter) Allow(ip string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	b, ok := l.buckets[ip]
	if !ok {
		l.buckets[ip] = &bucket{windowStart: time.Now()}
		return true, 0
	}

	// Active lockout
	if !b.lockedUntil.IsZero() && time.Now().Before(b.lockedUntil) {
		return false, time.Until(b.lockedUntil)
	}

	// Reset window if 5 minutes have passed since first attempt
	if time.Since(b.windowStart) > 5*time.Minute {
		b.count = 0
		b.windowStart = time.Now()
		b.lockedUntil = time.Time{}
	}

	if b.count >= 5 {
		b.lockedUntil = time.Now().Add(15 * time.Minute)
		return false, 15 * time.Minute
	}

	return true, 0
}

// Record increments the attempt count for the given IP.
// Call this after every failed login attempt.
func (l *LoginRateLimiter) Record(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[ip]
	if !ok {
		l.buckets[ip] = &bucket{count: 1, windowStart: time.Now()}
		return
	}
	b.count++
}

// Sweep removes old buckets that are no longer relevant.
func (l *LoginRateLimiter) Sweep() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for ip, b := range l.buckets {
		expired := b.lockedUntil.IsZero() && time.Since(b.windowStart) > 30*time.Minute
		lockExpired := !b.lockedUntil.IsZero() && time.Now().After(b.lockedUntil.Add(30*time.Minute))
		if expired || lockExpired {
			delete(l.buckets, ip)
		}
	}
}
