package auth

import (
	"testing"
	"time"
)

func TestLoginRateLimiter_AllowAndRecord(t *testing.T) {
	rl := NewLoginRateLimiter()

	// Five failed attempts should lock the IP.
	for i := 0; i < 5; i++ {
		ok, _ := rl.Allow("1.2.3.4")
		if !ok {
			t.Fatalf("Allow returned false before 5 attempts (attempt %d)", i+1)
		}
		rl.Record("1.2.3.4")
	}

	ok, retryAfter := rl.Allow("1.2.3.4")
	if ok {
		t.Fatal("Allow returned true after 5 failed attempts — expected lockout")
	}
	if retryAfter <= 0 {
		t.Errorf("retryAfter = %v, want > 0", retryAfter)
	}
}

// TestLoginRateLimiter_SweepPrunesBuckets verifies that Sweep removes
// expired buckets so the map doesn't grow unbounded.
func TestLoginRateLimiter_SweepPrunesBuckets(t *testing.T) {
	rl := NewLoginRateLimiter()

	// Register an attempt far in the past by manipulating the bucket directly.
	rl.mu.Lock()
	rl.buckets["10.0.0.1"] = &bucket{
		count:       1,
		windowStart: time.Now().Add(-31 * time.Minute), // past 30-min expiry
	}
	rl.mu.Unlock()

	// Before sweep: bucket exists.
	rl.mu.Lock()
	_, exists := rl.buckets["10.0.0.1"]
	rl.mu.Unlock()
	if !exists {
		t.Fatal("bucket should exist before Sweep")
	}

	rl.Sweep()

	// After sweep: bucket should be gone.
	rl.mu.Lock()
	_, exists = rl.buckets["10.0.0.1"]
	rl.mu.Unlock()
	if exists {
		t.Fatal("Sweep should have removed the expired bucket")
	}
}

// TestLoginRateLimiter_SweepPreservesActiveBuckets verifies that Sweep does
// not remove buckets that are still within the active window.
func TestLoginRateLimiter_SweepPreservesActiveBuckets(t *testing.T) {
	rl := NewLoginRateLimiter()

	// Recent attempt.
	rl.Allow("10.0.0.2")
	rl.Record("10.0.0.2")

	rl.Sweep()

	rl.mu.Lock()
	_, exists := rl.buckets["10.0.0.2"]
	rl.mu.Unlock()
	if !exists {
		t.Error("Sweep removed an active (non-expired) bucket")
	}
}

// TestLoginRateLimiter_AllowAfterSweep verifies that after Sweep removes a
// stale bucket the IP is allowed to attempt login again.
func TestLoginRateLimiter_AllowAfterSweep(t *testing.T) {
	rl := NewLoginRateLimiter()

	// Simulate expired lockout.
	rl.mu.Lock()
	rl.buckets["10.0.0.3"] = &bucket{
		count:       6,
		windowStart: time.Now().Add(-40 * time.Minute),
		lockedUntil: time.Now().Add(-31 * time.Minute), // lockout also expired
	}
	rl.mu.Unlock()

	rl.Sweep()

	ok, _ := rl.Allow("10.0.0.3")
	if !ok {
		t.Error("Allow should return true for a swept (removed) IP; bucket should be fresh")
	}
}
