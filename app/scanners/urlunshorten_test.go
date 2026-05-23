package scanners

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/izm1chael/mailhook/config"
	"github.com/izm1chael/mailhook/db"
	"github.com/izm1chael/mailhook/pipeline"
)

// mockFeedManager stubs the feedManager interface for unshorten tests.
type mockFeedManagerUnshorten struct {
	malicious map[string]struct{}
}

func (m *mockFeedManagerUnshorten) ContainsURL(rawURL string) bool {
	_, ok := m.malicious[rawURL]
	return ok
}

func (m *mockFeedManagerUnshorten) LookupURL(rawURL string) (feed, threatType string, ok bool) {
	if _, found := m.malicious[rawURL]; found {
		return "urlhaus", "malware", true
	}
	return "", "", false
}

func (m *mockFeedManagerUnshorten) LookupURLExact(rawURL string) (feed, threatType string, ok bool) {
	return m.LookupURL(rawURL)
}

func testUnshortenCfg(maxHops int, rateLimit, rateBurst int, perURLTO time.Duration) *config.Config {
	return &config.Config{
		URLUnshortenEnabled:       true,
		URLUnshortenMaxHops:       maxHops,
		URLUnshortenPerURLTimeout: perURLTO,
		URLUnshortenRateLimit:     rateLimit,
		URLUnshortenRateBurst:     rateBurst,
	}
}

func defaultUnshortenCfg() *config.Config {
	return testUnshortenCfg(3, 100, 100, 5*time.Second)
}

// newUnshortenScanner creates a scanner with the real SSRF guard (blocks localhost).
func newUnshortenScanner(t *testing.T, feeds feedManager, cfg *config.Config) *URLUnshorten {
	t.Helper()
	return NewURLUnshorten(feeds, cfg, newTestLogger())
}

// newUnshortenScannerNoSSRF creates a scanner with SSRF disabled for localhost-redirect tests.
// Both the pre-check hook and the transport DialContext are bypassed so httptest servers
// (which use 127.0.0.1) can be reached.
func newUnshortenScannerNoSSRF(t *testing.T, feeds feedManager, cfg *config.Config) *URLUnshorten {
	t.Helper()
	s := NewURLUnshorten(feeds, cfg, newTestLogger())
	s.ssrfBlocked = func(string) bool { return false }
	s.SetHTTPClient(&http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{DisableKeepAlives: true},
	})
	return s
}

func TestURLUnshorten_NoURLs(t *testing.T) {
	s := newUnshortenScanner(t, &mockFeedManagerUnshorten{}, defaultUnshortenCfg())
	email := &pipeline.Email{}
	res := s.Scan(context.Background(), email)
	if res.Verdict != "clean" {
		t.Fatalf("expected clean, got %s", res.Verdict)
	}
}

func TestURLUnshorten_Disabled(t *testing.T) {
	cfg := defaultUnshortenCfg()
	cfg.URLUnshortenEnabled = false
	s := newUnshortenScanner(t, &mockFeedManagerUnshorten{}, cfg)
	email := &pipeline.Email{URLs: []string{"http://example.com"}}
	res := s.Scan(context.Background(), email)
	if res.Verdict != "skip" {
		t.Fatalf("expected skip, got %s", res.Verdict)
	}
}

func TestURLUnshorten_DisabledAtRuntime(t *testing.T) {
	s := newUnshortenScanner(t, &mockFeedManagerUnshorten{}, defaultUnshortenCfg())
	s.SetEnabled(false)
	if s.IsEnabled() {
		t.Fatal("expected IsEnabled to return false")
	}
	email := &pipeline.Email{URLs: []string{"http://example.com"}}
	res := s.Scan(context.Background(), email)
	if res.Verdict != "skip" {
		t.Fatalf("expected skip, got %s", res.Verdict)
	}
}

func TestURLUnshorten_NoRedirect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// SSRF disabled because httptest servers use 127.0.0.1.
	s := newUnshortenScannerNoSSRF(t, &mockFeedManagerUnshorten{}, defaultUnshortenCfg())
	email := &pipeline.Email{URLs: []string{srv.URL + "/page"}}
	res := s.Scan(context.Background(), email)
	// No redirects → finalURL == rawURL → nothing recorded
	if res.Verdict != "clean" {
		t.Fatalf("expected clean, got %s", res.Verdict)
	}
	if res.Matches != nil {
		t.Fatal("expected no matches for non-redirected URL")
	}
}

func TestURLUnshorten_SingleRedirect_Clean(t *testing.T) {
	dest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer dest.Close()

	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, dest.URL+"/final", http.StatusMovedPermanently)
	}))
	defer redir.Close()

	// SSRF disabled because httptest servers use 127.0.0.1.
	s := newUnshortenScannerNoSSRF(t, &mockFeedManagerUnshorten{}, defaultUnshortenCfg())
	email := &pipeline.Email{URLs: []string{redir.URL + "/start"}}
	res := s.Scan(context.Background(), email)

	if res.Verdict != "clean" {
		t.Fatalf("expected clean, got %s", res.Verdict)
	}
	var hits []db.ResolvedURLHit
	if err := json.Unmarshal(res.Matches, &hits); err != nil {
		t.Fatalf("unmarshal hits: %v", err)
	}
	if len(hits) != 1 {
		t.Fatalf("expected 1 hit, got %d", len(hits))
	}
	if hits[0].Hops != 1 {
		t.Errorf("expected 1 hop, got %d", hits[0].Hops)
	}
	if hits[0].Feed != "" {
		t.Errorf("expected no feed match, got %q", hits[0].Feed)
	}
	if hits[0].Blocked {
		t.Error("expected not blocked")
	}
}

func TestURLUnshorten_SingleRedirect_Malicious(t *testing.T) {
	dest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer dest.Close()

	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, dest.URL+"/malware", http.StatusFound)
	}))
	defer redir.Close()

	feeds := &mockFeedManagerUnshorten{
		malicious: map[string]struct{}{dest.URL + "/malware": {}},
	}
	// SSRF disabled because httptest servers use 127.0.0.1.
	s := newUnshortenScannerNoSSRF(t, feeds, defaultUnshortenCfg())
	email := &pipeline.Email{URLs: []string{redir.URL + "/start"}}
	res := s.Scan(context.Background(), email)

	if res.Verdict != "malicious" {
		t.Fatalf("expected malicious, got %s", res.Verdict)
	}
	var hits []db.ResolvedURLHit
	if err := json.Unmarshal(res.Matches, &hits); err != nil {
		t.Fatalf("unmarshal hits: %v", err)
	}
	if len(hits) != 1 || hits[0].Feed != "urlhaus" {
		t.Errorf("expected feed=urlhaus hit, got %+v", hits)
	}
}

func TestURLUnshorten_MaxHopsEnforced(t *testing.T) {
	var servers []*httptest.Server
	// Chain: srv0 → srv1 → srv2 → srv3 → srv4 (final, 200)
	// With maxHops=3 we should stop at srv3 and return srv3 URL as final.
	// We build from the tail.
	final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer final.Close()
	servers = append(servers, final)

	for i := 0; i < 4; i++ {
		nextURL := servers[len(servers)-1].URL + "/hop"
		srv := httptest.NewServer(http.HandlerFunc(func(nextU string) http.HandlerFunc {
			return func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, nextU, http.StatusFound)
			}
		}(nextURL)))
		defer srv.Close()
		servers = append(servers, srv)
	}
	// servers[4] is the entry point (redirects 4 times before reaching final)
	entryURL := servers[len(servers)-1].URL + "/start"

	cfg := testUnshortenCfg(3, 100, 100, 5*time.Second)
	// SSRF disabled because httptest servers use 127.0.0.1.
	s := newUnshortenScannerNoSSRF(t, &mockFeedManagerUnshorten{}, cfg)
	email := &pipeline.Email{URLs: []string{entryURL}}
	res := s.Scan(context.Background(), email)

	if res.Verdict != "clean" {
		t.Fatalf("expected clean, got %s", res.Verdict)
	}

	var hits []db.ResolvedURLHit
	if err := json.Unmarshal(res.Matches, &hits); err != nil {
		t.Fatalf("unmarshal hits: %v", err)
	}
	if len(hits) == 0 {
		t.Fatal("expected at least one hit")
	}
	if hits[0].Hops > 3 {
		t.Errorf("expected at most 3 hops, got %d", hits[0].Hops)
	}
}

func TestURLUnshorten_SSRFBlock_Loopback(t *testing.T) {
	// Build a server that tries to redirect to a loopback address.
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.1:9999/admin", http.StatusFound)
	}))
	defer redir.Close()

	s := newUnshortenScanner(t, &mockFeedManagerUnshorten{}, defaultUnshortenCfg())
	email := &pipeline.Email{URLs: []string{redir.URL + "/start"}}
	res := s.Scan(context.Background(), email)

	if res.Verdict != "clean" {
		t.Fatalf("expected clean (SSRF blocked), got %s", res.Verdict)
	}

	var hits []db.ResolvedURLHit
	if err := json.Unmarshal(res.Matches, &hits); err != nil {
		t.Fatalf("unmarshal hits: %v", err)
	}
	if len(hits) == 0 || !hits[0].Blocked {
		t.Errorf("expected blocked=true in hit, got %+v", hits)
	}
}

func TestURLUnshorten_SSRFBlock_RFC1918(t *testing.T) {
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://192.168.1.1/admin", http.StatusFound)
	}))
	defer redir.Close()

	s := newUnshortenScanner(t, &mockFeedManagerUnshorten{}, defaultUnshortenCfg())
	email := &pipeline.Email{URLs: []string{redir.URL + "/start"}}
	res := s.Scan(context.Background(), email)

	var hits []db.ResolvedURLHit
	if err := json.Unmarshal(res.Matches, &hits); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(hits) == 0 || !hits[0].Blocked {
		t.Errorf("expected blocked RFC1918 hit, got %+v", hits)
	}
}

func TestURLUnshorten_SSRFBlock_LinkLocal(t *testing.T) {
	// 169.254.169.254 — AWS instance metadata endpoint
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
	}))
	defer redir.Close()

	s := newUnshortenScanner(t, &mockFeedManagerUnshorten{}, defaultUnshortenCfg())
	email := &pipeline.Email{URLs: []string{redir.URL + "/start"}}
	res := s.Scan(context.Background(), email)

	var hits []db.ResolvedURLHit
	if res.Matches != nil {
		_ = json.Unmarshal(res.Matches, &hits)
	}
	if len(hits) > 0 && !hits[0].Blocked {
		t.Errorf("expected blocked for link-local, got %+v", hits)
	}
}

func TestURLUnshorten_RateLimitSkips(t *testing.T) {
	// Rate limit: 1 per second, burst 1 → only first URL gets a token.
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		http.Redirect(w, r, "http://example.com/dest", http.StatusFound)
	}))
	defer srv.Close()

	cfg := testUnshortenCfg(3, 1, 1, 5*time.Second)
	s := newUnshortenScanner(t, &mockFeedManagerUnshorten{}, cfg)

	// Exhaust the burst immediately.
	s.limiter.Allow()

	email := &pipeline.Email{URLs: []string{
		srv.URL + "/url1",
		srv.URL + "/url2",
		srv.URL + "/url3",
	}}
	res := s.Scan(context.Background(), email)

	// All URLs should be skipped (rate limited) — scanner returns clean, no error.
	if res.Verdict != "clean" {
		t.Fatalf("expected clean when rate limited, got %s", res.Verdict)
	}
	if callCount != 0 {
		t.Errorf("expected 0 HTTP calls when rate limited, got %d", callCount)
	}
}

func TestURLUnshorten_NetworkError(t *testing.T) {
	// Point at a port that immediately refuses connections.
	s := newUnshortenScanner(t, &mockFeedManagerUnshorten{}, defaultUnshortenCfg())
	email := &pipeline.Email{URLs: []string{"http://127.0.0.1:1/bad"}}
	res := s.Scan(context.Background(), email)
	// Network errors → URL is skipped, scanner returns clean.
	if res.Verdict != "clean" {
		t.Fatalf("expected clean on network error, got %s", res.Verdict)
	}
}

func TestURLUnshorten_ContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(10 * time.Second) // block forever
	}))
	defer srv.Close()

	cfg := testUnshortenCfg(3, 100, 100, 100*time.Millisecond)
	s := newUnshortenScanner(t, &mockFeedManagerUnshorten{}, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	email := &pipeline.Email{URLs: []string{srv.URL + "/slow"}}
	res := s.Scan(ctx, email)
	// Should return within the context deadline.
	if res.Verdict != "clean" {
		t.Fatalf("expected clean on timeout, got %s", res.Verdict)
	}
}

func TestURLUnshorten_RelativeRedirect(t *testing.T) {
	// Server redirects /start → /dest (relative), then serves /dest as 200.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/dest" {
			w.WriteHeader(http.StatusOK)
			return
		}
		// Relative redirect — scanner must resolve against current URL.
		w.Header().Set("Location", "/dest")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	// SSRF disabled because httptest servers use 127.0.0.1.
	s := newUnshortenScannerNoSSRF(t, &mockFeedManagerUnshorten{}, defaultUnshortenCfg())
	email := &pipeline.Email{URLs: []string{srv.URL + "/start"}}
	res := s.Scan(context.Background(), email)

	if res.Verdict != "clean" {
		t.Fatalf("expected clean, got %s", res.Verdict)
	}
	// One redirect followed → hit recorded.
	var hits []db.ResolvedURLHit
	if res.Matches == nil {
		t.Fatal("expected Matches to be non-nil after redirect")
	}
	if err := json.Unmarshal(res.Matches, &hits); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(hits) != 1 {
		t.Fatalf("expected 1 hit, got %d", len(hits))
	}
	if hits[0].Hops != 1 {
		t.Errorf("expected hops=1, got %d", hits[0].Hops)
	}
	if !strings.Contains(hits[0].ResolvedURL, "/dest") {
		t.Errorf("expected ResolvedURL to contain /dest, got %q", hits[0].ResolvedURL)
	}
}
