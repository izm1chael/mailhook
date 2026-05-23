package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/izm1chael/mailhook/db"
)

// TestEncryptSetting verifies the encryptSetting helper encrypts when a key is
// configured and returns plaintext unchanged when no key is set.
func TestEncryptSetting(t *testing.T) {
	secret := "supersecret"

	// Without an encryption key: value is returned as-is.
	db.SetEncryptionKey(nil)
	got := encryptSetting(secret)
	if got != secret {
		t.Errorf("without key: want %q, got %q", secret, got)
	}

	// With a 32-byte key: result must be the enc: prefix and round-trip cleanly.
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	db.SetEncryptionKey(key)
	t.Cleanup(func() { db.SetEncryptionKey(nil) })

	enc := encryptSetting(secret)
	if !strings.HasPrefix(enc, "enc:") {
		t.Errorf("with key: want enc: prefix, got %q", enc)
	}

	var es db.EncryptedString
	if err := es.Scan(enc); err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	if string(es) != secret {
		t.Errorf("round-trip: want %q, got %q", secret, string(es))
	}
}

// trackingRefresher records whether Refresh was called and captures the context
// it was called with so we can verify it outlives the HTTP request.
// It blocks inside Refresh until release is closed so the test can inspect the
// context before the goroutine's defer cancel() fires.
type trackingRefresher struct {
	called  atomic.Bool
	gotCtx  context.Context
	started chan struct{}
	release chan struct{} // close to unblock Refresh
}

func (r *trackingRefresher) Refresh(ctx context.Context) {
	r.gotCtx = ctx
	r.called.Store(true)
	close(r.started)
	<-r.release
}

// TestFeedsRefresh_Returns202Immediately verifies the handler returns 202 at once
// without waiting for the refresh goroutine to complete.
func TestFeedsRefresh_Returns202Immediately(t *testing.T) {
	tr := &trackingRefresher{started: make(chan struct{}), release: make(chan struct{})}
	t.Cleanup(func() { close(tr.release) }) // unblock Refresh when test ends
	h := &SettingsHandler{feeds: tr}

	req := httptest.NewRequest(http.MethodPost, "/api/settings/feeds-refresh", nil)
	rec := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		h.FeedsRefresh(rec, req)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("FeedsRefresh handler did not return within 500ms")
	}

	if rec.Code != http.StatusAccepted {
		t.Errorf("status = %d, want 202", rec.Code)
	}
}

// TestFeedsRefresh_ContextDetachedFromRequest verifies the goroutine's context
// does not inherit cancellation from the HTTP request context.
func TestFeedsRefresh_ContextDetachedFromRequest(t *testing.T) {
	tr := &trackingRefresher{started: make(chan struct{}), release: make(chan struct{})}
	h := &SettingsHandler{feeds: tr}

	// Use a cancellable context to simulate the HTTP request lifecycle.
	reqCtx, reqCancel := context.WithCancel(context.Background())
	defer reqCancel()
	req := httptest.NewRequest(http.MethodPost, "/api/settings/feeds-refresh", nil).WithContext(reqCtx)
	rec := httptest.NewRecorder()

	h.FeedsRefresh(rec, req)

	// Wait for Refresh to start (it blocks on tr.release).
	select {
	case <-tr.started:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Refresh was not called within 500ms")
	}

	// Cancel the originating HTTP request context while Refresh is still running.
	reqCancel()
	time.Sleep(20 * time.Millisecond)

	// The context passed to Refresh must NOT be cancelled — it must be detached.
	if tr.gotCtx.Err() != nil {
		t.Errorf("Refresh context was cancelled when the HTTP request context was cancelled; "+
			"want a detached context: %v", tr.gotCtx.Err())
	}

	// Allow Refresh to return so the goroutine can clean up.
	close(tr.release)
}
