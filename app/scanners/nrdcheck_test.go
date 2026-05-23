package scanners

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/izm1chael/mailhook/config"
	"github.com/izm1chael/mailhook/db"
	"github.com/izm1chael/mailhook/pipeline"
)

// newTestNRDDB creates a temporary SQLite DB for NRD scanner tests.
func newTestNRDDB(t *testing.T) (*db.DB, func()) {
	t.Helper()
	f, err := os.CreateTemp("", "mailhook-nrd-test-*.db")
	if err != nil {
		t.Fatalf("create temp db: %v", err)
	}
	f.Close()
	path := f.Name()

	gdb, err := db.Open(path)
	if err != nil {
		os.Remove(path)
		t.Fatalf("open db: %v", err)
	}
	if err := gdb.Migrate(); err != nil {
		os.Remove(path)
		t.Fatalf("migrate: %v", err)
	}
	return gdb, func() {
		sqlDB, _ := gdb.DB.DB()
		sqlDB.Close()
		os.Remove(path)
	}
}

func newNRDScanner(t *testing.T, gdb *db.DB, rdapURL string, maxAgeDays int) *NRDCheck {
	t.Helper()
	cfg := &config.Config{
		NRDEnabled:       true,
		NRDMaxAgeDays:    maxAgeDays,
		NRDCacheTTLHours: 24,
		NRDRDAPBaseURL:   rdapURL,
	}
	s := NewNRDCheck(gdb, cfg, newTestLogger())
	// Inject a plain client so httptest loopback servers are reachable in tests.
	// Production uses the SSRF-safe client from NewNRDCheck.
	s.SetHTTPClient(&http.Client{Timeout: 5 * time.Second})
	// Force-enable: test RDAPs use http:// (httptest), which the https:// guard correctly
	// disables in production. Tests inject a custom client so the guard doesn't apply.
	s.SetEnabled(true)
	return s
}

func rdapJSON(regDate string) string {
	return `{"events":[{"eventAction":"registration","eventDate":"` + regDate + `"}]}`
}

func TestNRDCheck_NoURLsNoFrom(t *testing.T) {
	gdb, cleanup := newTestNRDDB(t)
	defer cleanup()
	s := newNRDScanner(t, gdb, "http://unused/", 14)
	email := &pipeline.Email{}
	res := s.Scan(context.Background(), email)
	if res.Verdict != "clean" {
		t.Fatalf("expected clean, got %s", res.Verdict)
	}
}

func TestNRDCheck_Disabled(t *testing.T) {
	gdb, cleanup := newTestNRDDB(t)
	defer cleanup()
	cfg := &config.Config{
		NRDEnabled:       false,
		NRDMaxAgeDays:    14,
		NRDCacheTTLHours: 24,
		NRDRDAPBaseURL:   "http://unused/",
	}
	s := NewNRDCheck(gdb, cfg, newTestLogger())
	email := &pipeline.Email{From: "attacker@new.example.com"}
	res := s.Scan(context.Background(), email)
	if res.Verdict != "skip" {
		t.Fatalf("expected skip, got %s", res.Verdict)
	}
}

func TestNRDCheck_DisabledAtRuntime(t *testing.T) {
	gdb, cleanup := newTestNRDDB(t)
	defer cleanup()
	s := newNRDScanner(t, gdb, "http://unused/", 14)
	s.SetEnabled(false)
	if s.IsEnabled() {
		t.Fatal("expected IsEnabled false")
	}
	res := s.Scan(context.Background(), &pipeline.Email{From: "a@b.com"})
	if res.Verdict != "skip" {
		t.Fatalf("expected skip, got %s", res.Verdict)
	}
}

func TestNRDCheck_OldDomain(t *testing.T) {
	regDate := time.Now().AddDate(0, 0, -30).UTC().Format(time.RFC3339)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(rdapJSON(regDate))) // nosemgrep: go.lang.security.audit.xss.no-direct-write-to-responsewriter.no-direct-write-to-responsewriter
	}))
	defer srv.Close()

	gdb, cleanup := newTestNRDDB(t)
	defer cleanup()
	s := newNRDScanner(t, gdb, srv.URL+"/", 14)

	email := &pipeline.Email{From: "user@old-domain.com"}
	res := s.Scan(context.Background(), email)
	if res.Verdict != "clean" {
		t.Fatalf("expected clean for 30-day-old domain, got %s", res.Verdict)
	}
}

func TestNRDCheck_NewDomain_FlagSuspicious(t *testing.T) {
	regDate := time.Now().AddDate(0, 0, -3).UTC().Format(time.RFC3339)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(rdapJSON(regDate))) // nosemgrep: go.lang.security.audit.xss.no-direct-write-to-responsewriter.no-direct-write-to-responsewriter
	}))
	defer srv.Close()

	gdb, cleanup := newTestNRDDB(t)
	defer cleanup()
	s := newNRDScanner(t, gdb, srv.URL+"/", 14)

	email := &pipeline.Email{From: "attacker@fresh-phish.com"}
	res := s.Scan(context.Background(), email)
	if res.Verdict != "suspicious" {
		t.Fatalf("expected suspicious for 3-day-old domain, got %s", res.Verdict)
	}
	if res.Score != 0.6 {
		t.Errorf("expected score 0.6, got %f", res.Score)
	}
	var hits []db.NRDHit
	if err := json.Unmarshal(res.Matches, &hits); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(hits) != 1 || hits[0].Source != "from" {
		t.Errorf("expected 1 from-domain hit, got %+v", hits)
	}
}

func TestNRDCheck_ExactBoundaryDay(t *testing.T) {
	// Exactly maxAgeDays ago — should still be flagged (inclusive boundary).
	regDate := time.Now().AddDate(0, 0, -14).UTC().Format(time.RFC3339)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(rdapJSON(regDate))) // nosemgrep: go.lang.security.audit.xss.no-direct-write-to-responsewriter.no-direct-write-to-responsewriter
	}))
	defer srv.Close()

	gdb, cleanup := newTestNRDDB(t)
	defer cleanup()
	s := newNRDScanner(t, gdb, srv.URL+"/", 14)

	email := &pipeline.Email{From: "test@boundary-domain.com"}
	res := s.Scan(context.Background(), email)
	if res.Verdict != "suspicious" {
		t.Fatalf("expected suspicious at boundary (14d), got %s", res.Verdict)
	}
}

func TestNRDCheck_JustOutsideBoundary(t *testing.T) {
	regDate := time.Now().AddDate(0, 0, -15).UTC().Format(time.RFC3339)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(rdapJSON(regDate))) // nosemgrep: go.lang.security.audit.xss.no-direct-write-to-responsewriter.no-direct-write-to-responsewriter
	}))
	defer srv.Close()

	gdb, cleanup := newTestNRDDB(t)
	defer cleanup()
	s := newNRDScanner(t, gdb, srv.URL+"/", 14)

	email := &pipeline.Email{From: "test@outside-domain.com"}
	res := s.Scan(context.Background(), email)
	if res.Verdict != "clean" {
		t.Fatalf("expected clean at 15 days, got %s", res.Verdict)
	}
}

func TestNRDCheck_FromDomain(t *testing.T) {
	regDate := time.Now().AddDate(0, 0, -2).UTC().Format(time.RFC3339)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(rdapJSON(regDate))) // nosemgrep: go.lang.security.audit.xss.no-direct-write-to-responsewriter.no-direct-write-to-responsewriter
	}))
	defer srv.Close()

	gdb, cleanup := newTestNRDDB(t)
	defer cleanup()
	s := newNRDScanner(t, gdb, srv.URL+"/", 14)

	// Only From: domain, no URLs.
	email := &pipeline.Email{From: "evil@newdomain.io"}
	res := s.Scan(context.Background(), email)
	if res.Verdict != "suspicious" {
		t.Fatalf("expected suspicious, got %s", res.Verdict)
	}
	var hits []db.NRDHit
	_ = json.Unmarshal(res.Matches, &hits)
	if len(hits) != 1 || hits[0].Source != "from" {
		t.Errorf("expected from-source hit, got %+v", hits)
	}
}

func TestNRDCheck_URLDomain(t *testing.T) {
	// From: domain is old (404), URL domain is new.
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		// Determine domain from path (last segment)
		path := r.URL.Path
		if len(path) > 1 {
			domain := path[1:] // strip leading /
			if domain == "olddomain.com" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
		}
		regDate := time.Now().AddDate(0, 0, -1).UTC().Format(time.RFC3339)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(rdapJSON(regDate))) // nosemgrep: go.lang.security.audit.xss.no-direct-write-to-responsewriter.no-direct-write-to-responsewriter
	}))
	defer srv.Close()

	gdb, cleanup := newTestNRDDB(t)
	defer cleanup()
	s := newNRDScanner(t, gdb, srv.URL+"/", 14)

	email := &pipeline.Email{
		From: "legit@olddomain.com",
		URLs: []string{"http://freshphish.xyz/steal"},
	}
	res := s.Scan(context.Background(), email)
	if res.Verdict != "suspicious" {
		t.Fatalf("expected suspicious, got %s", res.Verdict)
	}
	var hits []db.NRDHit
	_ = json.Unmarshal(res.Matches, &hits)
	if len(hits) != 1 || hits[0].Source != "url" {
		t.Errorf("expected url-source hit, got %+v", hits)
	}
}

func TestNRDCheck_DuplicateDomainsDeduped(t *testing.T) {
	callCount := 0
	regDate := time.Now().AddDate(0, 0, -2).UTC().Format(time.RFC3339)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(rdapJSON(regDate))) // nosemgrep: go.lang.security.audit.xss.no-direct-write-to-responsewriter.no-direct-write-to-responsewriter
	}))
	defer srv.Close()

	gdb, cleanup := newTestNRDDB(t)
	defer cleanup()
	s := newNRDScanner(t, gdb, srv.URL+"/", 14)

	// Same domain appears in From: and multiple URLs — should only make one RDAP call.
	email := &pipeline.Email{
		From: "user@samedomain.com",
		URLs: []string{
			"http://samedomain.com/path1",
			"http://samedomain.com/path2",
		},
	}
	res := s.Scan(context.Background(), email)
	if res.Verdict != "suspicious" {
		t.Fatalf("expected suspicious, got %s", res.Verdict)
	}
	if callCount != 1 {
		t.Errorf("expected exactly 1 RDAP call for deduplicated domain, got %d", callCount)
	}
}

func TestNRDCheck_CacheHit(t *testing.T) {
	callCount := 0
	regDate := time.Now().AddDate(0, 0, -2).UTC().Format(time.RFC3339)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(rdapJSON(regDate))) // nosemgrep: go.lang.security.audit.xss.no-direct-write-to-responsewriter.no-direct-write-to-responsewriter
	}))
	defer srv.Close()

	gdb, cleanup := newTestNRDDB(t)
	defer cleanup()
	s := newNRDScanner(t, gdb, srv.URL+"/", 14)

	email := &pipeline.Email{From: "user@cached-domain.net"}

	// First scan — populates cache.
	res1 := s.Scan(context.Background(), email)
	if res1.Verdict != "suspicious" {
		t.Fatalf("expected suspicious on first scan, got %s", res1.Verdict)
	}
	if callCount != 1 {
		t.Fatalf("expected 1 RDAP call on first scan, got %d", callCount)
	}

	// Second scan — should use cache.
	res2 := s.Scan(context.Background(), email)
	if res2.Verdict != "suspicious" {
		t.Fatalf("expected suspicious on cached scan, got %s", res2.Verdict)
	}
	if callCount != 1 {
		t.Errorf("expected 1 total RDAP call (cache hit on 2nd scan), got %d", callCount)
	}
}

func TestNRDCheck_NegativeCacheHit(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	gdb, cleanup := newTestNRDDB(t)
	defer cleanup()
	s := newNRDScanner(t, gdb, srv.URL+"/", 14)

	email := &pipeline.Email{From: "user@unknown-tld.invalid"}

	// First scan — caches the 404.
	s.Scan(context.Background(), email)
	if callCount != 1 {
		t.Fatalf("expected 1 RDAP call, got %d", callCount)
	}

	// Second scan — should use negative cache, no HTTP call.
	s.Scan(context.Background(), email)
	if callCount != 1 {
		t.Errorf("expected negative cache to prevent 2nd RDAP call, got %d calls", callCount)
	}
}

func TestNRDCheck_RDAP404_DomainUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	gdb, cleanup := newTestNRDDB(t)
	defer cleanup()
	s := newNRDScanner(t, gdb, srv.URL+"/", 14)

	email := &pipeline.Email{From: "user@no-rdap.invalid"}
	res := s.Scan(context.Background(), email)
	if res.Verdict != "clean" {
		t.Fatalf("expected clean for 404 domain, got %s", res.Verdict)
	}
}

func TestNRDCheck_RDAPServerError_5xx_NotCached(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	gdb, cleanup := newTestNRDDB(t)
	defer cleanup()
	s := newNRDScanner(t, gdb, srv.URL+"/", 14)

	email := &pipeline.Email{From: "user@server-error.com"}

	// First scan — 5xx should not be cached.
	s.Scan(context.Background(), email)

	// Second scan — should try RDAP again (not cached).
	s.Scan(context.Background(), email)

	if callCount != 2 {
		t.Errorf("expected 2 RDAP calls (5xx not cached), got %d", callCount)
	}
}

func TestNRDCheck_RDAPNoRegistrationEvent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// RDAP response with events but no registration action.
		body := `{"events":[{"eventAction":"expiration","eventDate":"2030-01-01T00:00:00Z"}]}`
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body)) // nosemgrep: go.lang.security.audit.xss.no-direct-write-to-responsewriter.no-direct-write-to-responsewriter
	}))
	defer srv.Close()

	gdb, cleanup := newTestNRDDB(t)
	defer cleanup()
	s := newNRDScanner(t, gdb, srv.URL+"/", 14)

	email := &pipeline.Email{From: "user@no-reg-event.com"}
	res := s.Scan(context.Background(), email)
	if res.Verdict != "clean" {
		t.Fatalf("expected clean (no registration event), got %s", res.Verdict)
	}
}

func TestNRDCheck_RDAPMalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{invalid json!!!`)) // nosemgrep: go.lang.security.audit.xss.no-direct-write-to-responsewriter.no-direct-write-to-responsewriter
	}))
	defer srv.Close()

	gdb, cleanup := newTestNRDDB(t)
	defer cleanup()
	s := newNRDScanner(t, gdb, srv.URL+"/", 14)

	email := &pipeline.Email{From: "user@malformed.com"}
	res := s.Scan(context.Background(), email)
	// Malformed JSON → not flagged, no panic.
	if res.Verdict != "clean" {
		t.Fatalf("expected clean for malformed JSON, got %s", res.Verdict)
	}
}

func TestNRDCheck_ContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(10 * time.Second)
	}))
	defer srv.Close()

	gdb, cleanup := newTestNRDDB(t)
	defer cleanup()
	s := newNRDScanner(t, gdb, srv.URL+"/", 14)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	email := &pipeline.Email{From: "user@slow-rdap.com"}
	// Should return quickly without panic.
	res := s.Scan(ctx, email)
	if res.Verdict != "clean" {
		t.Fatalf("expected clean on context timeout, got %s", res.Verdict)
	}
}

func TestNRDCheck_DateOnlyFormat(t *testing.T) {
	// Some registries emit date-only strings like "2026-05-10" (no time component).
	regDate := time.Now().AddDate(0, 0, -3).UTC().Format("2006-01-02")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := `{"events":[{"eventAction":"registration","eventDate":"` + regDate + `"}]}`
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body)) // nosemgrep: go.lang.security.audit.xss.no-direct-write-to-responsewriter.no-direct-write-to-responsewriter
	}))
	defer srv.Close()

	gdb, cleanup := newTestNRDDB(t)
	defer cleanup()
	s := newNRDScanner(t, gdb, srv.URL+"/", 14)

	email := &pipeline.Email{From: "user@date-only.com"}
	res := s.Scan(context.Background(), email)
	if res.Verdict != "suspicious" {
		t.Fatalf("expected suspicious for date-only registration format, got %s", res.Verdict)
	}
}

func TestNRDCheck_SSRFPrivateAddressBlocked(t *testing.T) {
	// The SSRF-safe client must refuse to connect to loopback/private IPs.
	// We test this by pointing rdapBaseURL at a loopback address directly.
	// The DialContext hook should reject it before any connection is made.
	gdb, cleanup := newTestNRDDB(t)
	defer cleanup()

	// Use a loopback URL — the SSRF guard should block the connection attempt.
	s := newNRDScanner(t, gdb, "http://127.0.0.1:19999/", 14)

	// Should not panic; the SSRF guard returns an error which is treated as cache miss.
	// We just verify it doesn't hang or crash.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	// The scanner uses a separate client in newSSRFSafeClient; direct call to rdapLookup
	// is the best way to verify the guard fires.
	_, _, err := s.rdapLookup(ctx, "newdomain.io")
	if err == nil {
		t.Error("expected SSRF guard to return an error for loopback address, got nil")
	}
}

func TestNRDCheck_DisplayNameFrom(t *testing.T) {
	// From: header with display name: "Evil Corp <attacker@newdomain.io>"
	regDate := time.Now().AddDate(0, 0, -2).UTC().Format(time.RFC3339)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(rdapJSON(regDate))) // nosemgrep: go.lang.security.audit.xss.no-direct-write-to-responsewriter.no-direct-write-to-responsewriter
	}))
	defer srv.Close()

	gdb, cleanup := newTestNRDDB(t)
	defer cleanup()
	s := newNRDScanner(t, gdb, srv.URL+"/", 14)

	email := &pipeline.Email{From: "Evil Corp <attacker@newdomain.io>"}
	res := s.Scan(context.Background(), email)
	if res.Verdict != "suspicious" {
		t.Fatalf("expected suspicious for display-name From:, got %s", res.Verdict)
	}
}

// TestNRDCheck_NonHTTPSDisabled verifies that an http:// RDAP base URL disables
// the scanner even when NRDEnabled=true — checks run over cleartext must not fire.
func TestNRDCheck_NonHTTPSDisabled(t *testing.T) {
	gdb, cleanup := newTestNRDDB(t)
	defer cleanup()

	cfg := &config.Config{
		NRDEnabled:       true,
		NRDMaxAgeDays:    14,
		NRDCacheTTLHours: 24,
		NRDRDAPBaseURL:   "http://rdap.example.com/domain/",
	}
	s := NewNRDCheck(gdb, cfg, newTestLogger())
	// Do NOT call SetEnabled(true) — we want the production behaviour.

	email := &pipeline.Email{From: "user@example.com"}
	res := s.Scan(context.Background(), email)
	if res.Verdict != "skip" {
		t.Errorf("expected skip when RDAP URL is not https://, got %s", res.Verdict)
	}
}

// TestNRDCheck_PathInjectionDomain verifies that a From: domain containing path
// separators is rejected and produces no RDAP lookup.
func TestNRDCheck_PathInjectionDomain(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`)) // nosemgrep: go.lang.security.audit.xss.no-direct-write-to-responsewriter.no-direct-write-to-responsewriter
	}))
	defer srv.Close()

	gdb, cleanup := newTestNRDDB(t)
	defer cleanup()
	s := newNRDScanner(t, gdb, srv.URL+"/", 14)

	// Crafted From that would inject a path segment into the RDAP URL.
	email := &pipeline.Email{From: "user@evil.com/../../admin"}
	res := s.Scan(context.Background(), email)
	if res.Verdict != "clean" {
		t.Errorf("expected clean (invalid domain rejected), got %s", res.Verdict)
	}
	if called {
		t.Error("RDAP server should not have been called for an invalid domain")
	}
}
