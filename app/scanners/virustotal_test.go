package scanners_test

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/izm1chael/mailhook/db"
	"github.com/izm1chael/mailhook/pipeline"
	"github.com/izm1chael/mailhook/scanners"
	"gorm.io/gorm"
)

func openVTTestDB(t *testing.T) *db.DB {
	t.Helper()
	gdb, err := db.Open(filepath.Join(t.TempDir(), "vt_test.db"))
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	if err := gdb.Migrate(); err != nil {
		t.Fatalf("db.Migrate: %v", err)
	}
	return gdb
}

func seedVTCache(t *testing.T, gdb *db.DB, sha256 string, positives, total int, fetchedAt time.Time) {
	t.Helper()
	err := gdb.Write(func(tx *gorm.DB) error {
		return tx.Save(&db.VTHashCache{
			SHA256:    sha256,
			Positives: positives,
			Total:     total,
			FetchedAt: fetchedAt,
		}).Error
	})
	if err != nil {
		t.Fatalf("seedVTCache: %v", err)
	}
}

// TestVTCacheTTL_PositiveExpiry asserts that a stale positive result causes an
// API call instead of being served from cache.
func TestVTCacheTTL_PositiveExpiry(t *testing.T) {
	gdb := openVTTestDB(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	apiCalled := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiCalled = true
		fmt.Fprint(w, `{"data":{"attributes":{"last_analysis_stats":{"malicious":2,"suspicious":0,"undetected":60,"harmless":10}}}}`)
	}))
	t.Cleanup(srv.Close)

	// Seed a stale positive result (25 hours old with 24h TTL).
	const sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	seedVTCache(t, gdb, sha, 1, 72, time.Now().Add(-25*time.Hour))

	vt := scanners.NewVirusTotal("test-key", gdb, log, 24*time.Hour, 4*time.Hour)
	vt.SetVTBaseURL(srv.URL) // test hook to redirect to mock server

	email := &pipeline.Email{
		Attachments: []pipeline.Attachment{
			{SHA256: sha, IsDangerous: true, Filename: "test.exe"},
		},
	}
	result := vt.Scan(context.Background(), email)

	if !apiCalled {
		t.Error("expected API call for expired cache entry, but API was not called")
	}
	t.Logf("result: verdict=%s detail=%s", result.Verdict, result.Detail)
}

// TestVTCacheTTL_NotFoundExpiry asserts that a stale not-found (0/0) result
// triggers an API call after the shorter not-found TTL expires.
func TestVTCacheTTL_NotFoundExpiry(t *testing.T) {
	gdb := openVTTestDB(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	apiCalled := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiCalled = true
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)

	// Seed a stale not-found result (5 hours old with 4h TTL).
	const sha = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	seedVTCache(t, gdb, sha, 0, 0, time.Now().Add(-5*time.Hour))

	vt := scanners.NewVirusTotal("test-key", gdb, log, 24*time.Hour, 4*time.Hour)
	vt.SetVTBaseURL(srv.URL)

	email := &pipeline.Email{
		Attachments: []pipeline.Attachment{
			{SHA256: sha, IsDangerous: true, Filename: "test.exe"},
		},
	}
	vt.Scan(context.Background(), email)

	if !apiCalled {
		t.Error("expected API call for expired not-found cache entry, but API was not called")
	}
}

// TestVTCacheTTL_HitNotExpired asserts that a fresh cache entry is served
// without making an API call.
func TestVTCacheTTL_HitNotExpired(t *testing.T) {
	gdb := openVTTestDB(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	apiCalled := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiCalled = true
		fmt.Fprint(w, `{"data":{"attributes":{"last_analysis_stats":{"malicious":0,"suspicious":0,"undetected":72,"harmless":0}}}}`)
	}))
	t.Cleanup(srv.Close)

	// Seed a fresh result (1 hour old with 24h TTL).
	const sha = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	seedVTCache(t, gdb, sha, 0, 72, time.Now().Add(-1*time.Hour))

	vt := scanners.NewVirusTotal("test-key", gdb, log, 24*time.Hour, 4*time.Hour)
	vt.SetVTBaseURL(srv.URL)

	email := &pipeline.Email{
		Attachments: []pipeline.Attachment{
			{SHA256: sha, IsDangerous: true, Filename: "test.exe"},
		},
	}
	vt.Scan(context.Background(), email)

	if apiCalled {
		t.Error("API was called for a fresh (non-expired) cache entry; should have served from cache")
	}
}
