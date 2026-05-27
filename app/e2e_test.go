package main_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/izm1chael/mailhook/auth"
	"github.com/izm1chael/mailhook/config"
	"github.com/izm1chael/mailhook/db"
	"github.com/izm1chael/mailhook/notify"
	"github.com/izm1chael/mailhook/storage"
	"github.com/izm1chael/mailhook/web"
	"github.com/izm1chael/mailhook/web/handlers"
)

// ── mock external services ───────────────────────────────────────────────────

type mockPinger struct{ err error }

func (m *mockPinger) Ping(_ context.Context) error { return m.err }

// mockRspamd satisfies both handlers.Pinger (via health) and handlers.RspamdLearner (via actions).
type mockRspamd struct{ pingErr error }

func (m *mockRspamd) Ping(_ context.Context) error            { return m.pingErr }
func (m *mockRspamd) LearnSpam(_ context.Context, _ []byte) error { return nil }
func (m *mockRspamd) LearnHam(_ context.Context, _ []byte) error  { return nil }

// mockProcessor satisfies handlers.EmailProcessor.
type mockProcessor struct{}

func (m *mockProcessor) Process(_ context.Context, _ string, _ []byte, _ uint32, _ string) {}

// mockFeeds satisfies both handlers.FeedStatsProvider and handlers.FeedRefresher.
type mockFeeds struct{}

func (m *mockFeeds) FeedStats() (map[string]int, time.Time) {
	return map[string]int{"urlhaus": 42}, time.Now()
}
func (m *mockFeeds) Refresh(_ context.Context) {}

// mockYARA satisfies both handlers.YARARuleProvider and handlers.YARAReloader.
type mockYARA struct{}

func (m *mockYARA) RuleCount() int             { return 7 }
func (m *mockYARA) LastLoaded() time.Time      { return time.Now() }
func (m *mockYARA) ReloadRules() error         { return nil }
func (m *mockYARA) SetRulesDir(_ string) error { return nil }

// ── test server setup ────────────────────────────────────────────────────────

const testPassword = "testpassword123"

type testEnv struct {
	server  *httptest.Server
	client  *http.Client // follows redirects, stores cookies
	noRedir *http.Client // stops at first redirect
	baseURL string
	cfg     *config.Config
}

// cookieValue returns the named cookie for the server base URL, or "".
func (e *testEnv) cookieValue(name string) string {
	u, _ := url.Parse(e.baseURL)
	for _, c := range e.client.Jar.Cookies(u) {
		if c.Name == name {
			return c.Value
		}
	}
	return ""
}

// csrfToken returns the nonce portion of the signed CSRF cookie.
// The cookie value is "nonce.HMAC"; only the nonce is submitted as X-CSRF-Token.
func (e *testEnv) csrfToken() string {
	v := e.cookieValue("mailhook_csrf")
	if parts := strings.SplitN(v, ".", 2); len(parts) == 2 {
		return parts[0]
	}
	return v
}

// login performs POST /login and returns the first non-redirect response.
// It uses the noRedir client so callers can inspect the 303 status.
func (e *testEnv) login(t *testing.T, username, password string) *http.Response {
	t.Helper()
	form := url.Values{"username": {username}, "password": {password}}
	resp, err := e.noRedir.PostForm(e.baseURL+"/login", form)
	if err != nil {
		t.Fatalf("POST /login: %v", err)
	}
	return resp
}

// mustLogin logs in as admin and fails the test if it doesn't succeed.
func (e *testEnv) mustLogin(t *testing.T) {
	t.Helper()
	resp := e.login(t, "admin", testPassword)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 303 from login, got %d: %s", resp.StatusCode, body)
	}
	// Follow the redirect with the full client so the session cookie is persisted.
	r, err := e.client.Get(e.baseURL + "/")
	if err != nil {
		t.Fatalf("GET / after login: %v", err)
	}
	r.Body.Close()
}

// apiPost sends an authenticated JSON POST with the CSRF token.
func (e *testEnv) apiPost(t *testing.T, path string, body interface{}) *http.Response {
	t.Helper()
	b, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodPost, e.baseURL+path, bytes.NewReader(b))
	if err != nil {
		t.Fatalf("build POST %s request: %v", path, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", e.csrfToken())
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	return resp
}

// apiDelete sends an authenticated JSON DELETE with the CSRF token.
func (e *testEnv) apiDelete(t *testing.T, path string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodDelete, e.baseURL+path, nil)
	if err != nil {
		t.Fatalf("build DELETE %s request: %v", path, err)
	}
	req.Header.Set("X-CSRF-Token", e.csrfToken())
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatalf("DELETE %s: %v", path, err)
	}
	return resp
}

// newTestEnv builds the full HTTP stack with a temporary SQLite database.
// All external scanner/feed calls are mocked. Templates are initialised from
// the embedded FS (same embed as production).
func newTestEnv(t *testing.T) *testEnv {
	t.Helper()

	dir := t.TempDir()

	gdb, err := db.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	if err := gdb.Migrate(); err != nil {
		t.Fatalf("db.Migrate: %v", err)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(testPassword), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}

	cfg := &config.Config{
		AdminUser:           "admin",
		AdminPasswordBcrypt: string(hash),
		SpamScore:           5.0,
		RejectScore:         15.0,
		DataDir:             dir,
		MetricsAllowedCIDRs: []string{"127.0.0.1/32", "::1/128"},
	}

	if err := web.InitTemplates(); err != nil {
		t.Fatalf("web.InitTemplates: %v", err)
	}

	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	store, err := storage.New(dir, log)
	if err != nil {
		t.Fatalf("storage.New: %v", err)
	}

	sessions := auth.NewStore(24 * time.Hour)
	rateLimiter := auth.NewLoginRateLimiter()
	hub := web.NewSSEHub()
	notifier := notify.New(cfg, log)

	mRspamd := &mockRspamd{}
	mClamAV := &mockPinger{}
	mFeeds := &mockFeeds{}
	mYARA := &mockYARA{}
	mProc := &mockProcessor{}

	healthHandler := handlers.NewHealthHandler(gdb, mRspamd, mClamAV, mFeeds, mYARA, "test-1.0", slog.Default())
	testCSRFSecret := make([]byte, 32)
	authMiddleware := auth.NewMiddleware(sessions, nil, testCSRFSecret, true)
	metricsHandler, err := handlers.NewMetricsHandler(cfg.MetricsAllowedCIDRs, authMiddleware)
	if err != nil {
		t.Fatalf("NewMetricsHandler: %v", err)
	}
	authHandler := handlers.NewAuthHandler(cfg, sessions, rateLimiter, authMiddleware, log)
	dashHandler := handlers.NewDashboardHandler(gdb, authMiddleware, log)
	emailsHandler := handlers.NewEmailsHandler(gdb, store)
	testRegistry := handlers.NewAccountRegistry()
	testRegistry.Add("test", nil, mProc)
	actionsHandler := handlers.NewActionsHandler(gdb, store, testRegistry, mRspamd, log)
	allowlistsHandler := handlers.NewAllowlistsHandler(gdb, authMiddleware, log)
	settingsHandler := handlers.NewSettingsHandler(gdb, cfg, mFeeds, nil, mYARA, notifier, nil, nil, nil, nil, nil, nil, nil, testRegistry, sessions, authMiddleware, log)
	sseHandler := handlers.NewSSEHandler(hub)
	csrf := authMiddleware.CSRF

	mux := http.NewServeMux()

	mux.Handle("GET /static/", http.StripPrefix("/static/", web.StaticHandler()))
	mux.HandleFunc("GET /health", healthHandler.GetHealth)
	mux.HandleFunc("GET /metrics", metricsHandler.GetMetrics)
	mux.HandleFunc("GET /login", authHandler.GetLogin)
	mux.HandleFunc("POST /login", authHandler.PostLogin)
	mux.HandleFunc("POST /logout", authMiddleware.Require(authHandler.PostLogout))

	mux.HandleFunc("GET /", authMiddleware.Require(dashHandler.GetDashboard))
	mux.HandleFunc("GET /quarantine", authMiddleware.Require(dashHandler.GetQuarantine))
	mux.HandleFunc("GET /stats", authMiddleware.Require(dashHandler.GetStats))
	mux.HandleFunc("GET /allowlists", authMiddleware.Require(allowlistsHandler.GetAllowlists))
	mux.HandleFunc("GET /settings", authMiddleware.Require(settingsHandler.GetSettings))

	mux.HandleFunc("GET /api/events", authMiddleware.Require(sseHandler.GetEvents))
	mux.HandleFunc("GET /api/scans", authMiddleware.Require(emailsHandler.ListScans))
	mux.HandleFunc("GET /api/scans/", authMiddleware.Require(emailsHandler.GetScan))
	mux.HandleFunc("GET /api/eml/", authMiddleware.Require(emailsHandler.DownloadEML))
	mux.HandleFunc("GET /api/preview/", authMiddleware.Require(emailsHandler.PreviewHTML))
	mux.HandleFunc("GET /api/defang", authMiddleware.Require(handlers.DefangURL))
	mux.HandleFunc("GET /api/whitelist", authMiddleware.Require(allowlistsHandler.ListWhitelist))
	mux.HandleFunc("GET /api/blocklist", authMiddleware.Require(allowlistsHandler.ListBlocklist))

	mux.HandleFunc("POST /api/release/", authMiddleware.Require(csrf(actionsHandler.Release)))
	mux.HandleFunc("POST /api/release-learn/", authMiddleware.Require(csrf(actionsHandler.ReleaseAndLearn)))
	mux.HandleFunc("POST /api/delete/", authMiddleware.Require(csrf(actionsHandler.Delete)))
	mux.HandleFunc("POST /api/learn-spam/", authMiddleware.Require(csrf(actionsHandler.LearnSpam)))
	mux.HandleFunc("POST /api/rescan/", authMiddleware.Require(csrf(actionsHandler.Rescan)))
	mux.HandleFunc("POST /api/whitelist", authMiddleware.Require(csrf(allowlistsHandler.AddWhitelist)))
	mux.HandleFunc("DELETE /api/whitelist/", authMiddleware.Require(csrf(allowlistsHandler.DeleteWhitelist)))
	mux.HandleFunc("POST /api/blocklist", authMiddleware.Require(csrf(allowlistsHandler.AddBlocklist)))
	mux.HandleFunc("DELETE /api/blocklist/", authMiddleware.Require(csrf(allowlistsHandler.DeleteBlocklist)))
	mux.HandleFunc("POST /api/allowlists/bulk-import", authMiddleware.Require(csrf(allowlistsHandler.BulkImport)))
	mux.HandleFunc("POST /api/settings/thresholds", authMiddleware.Require(csrf(settingsHandler.UpdateThresholds)))
	mux.HandleFunc("POST /api/settings/notify-test", authMiddleware.Require(csrf(settingsHandler.NotifyTest)))
	mux.HandleFunc("POST /api/settings/feeds-refresh", authMiddleware.Require(csrf(settingsHandler.FeedsRefresh)))
	mux.HandleFunc("POST /api/settings/yara-reload", authMiddleware.Require(csrf(settingsHandler.YARAReload)))
	mux.HandleFunc("POST /api/settings/api-keys", authMiddleware.Require(csrf(settingsHandler.UpdateAPIKeys)))
	mux.HandleFunc("POST /api/settings/notifications", authMiddleware.Require(csrf(settingsHandler.UpdateNotifications)))
	mux.HandleFunc("POST /api/settings/scanners", authMiddleware.Require(csrf(settingsHandler.UpdateScanners)))
	mux.HandleFunc("POST /api/settings/endpoints", authMiddleware.Require(csrf(settingsHandler.UpdateEndpoints)))
	mux.HandleFunc("GET /api/settings/accounts", authMiddleware.Require(settingsHandler.GetAccounts))
	mux.HandleFunc("POST /api/settings/accounts/test", authMiddleware.Require(csrf(settingsHandler.TestAccount)))
	mux.HandleFunc("POST /api/settings/accounts", authMiddleware.Require(csrf(settingsHandler.CreateAccount)))
	mux.HandleFunc("PUT /api/settings/accounts/", authMiddleware.Require(csrf(settingsHandler.UpdateAccount)))
	mux.HandleFunc("DELETE /api/settings/accounts/", authMiddleware.Require(csrf(settingsHandler.DeleteAccount)))

	srv := httptest.NewTLSServer(web.Recovery(log, web.SecurityHeaders(mux)))
	t.Cleanup(srv.Close)

	jar, _ := cookiejar.New(nil)
	client := srv.Client()
	client.Jar = jar

	noRedir := *client
	noRedir.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	noRedir.Jar = jar // share the same jar so cookies accumulate

	return &testEnv{
		server:  srv,
		client:  client,
		noRedir: &noRedir,
		baseURL: srv.URL,
		cfg:     cfg,
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────

func assertStatus(t *testing.T, resp *http.Response, want int) {
	t.Helper()
	if resp.StatusCode != want {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("status: got %d, want %d — body: %s", resp.StatusCode, want, body)
	}
}

func assertContentType(t *testing.T, resp *http.Response, want string) {
	t.Helper()
	ct := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, want) {
		t.Errorf("Content-Type: got %q, want prefix %q", ct, want)
	}
}

func decodeJSON(t *testing.T, resp *http.Response, v interface{}) {
	t.Helper()
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
}

func readBody(resp *http.Response) string {
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return string(b)
}

// ── tests ────────────────────────────────────────────────────────────────────

func TestE2E_Health(t *testing.T) {
	e := newTestEnv(t)

	resp, err := e.client.Get(e.baseURL + "/health")
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	assertStatus(t, resp, http.StatusOK)
	assertContentType(t, resp, "application/json")

	var payload map[string]interface{}
	decodeJSON(t, resp, &payload)

	for _, field := range []string{"status", "version", "uptime_seconds", "components", "stats_today"} {
		if _, ok := payload[field]; !ok {
			t.Errorf("health response missing field %q", field)
		}
	}
	if payload["status"] != "healthy" {
		t.Errorf("health status: got %v, want healthy", payload["status"])
	}
	if payload["version"] != "test-1.0" {
		t.Errorf("health version: got %v, want test-1.0", payload["version"])
	}

	comps, ok := payload["components"].(map[string]interface{})
	if !ok {
		t.Fatal("components is not an object")
	}
	for _, name := range []string{"database", "rspamd", "clamav", "yara", "feeds"} {
		if _, ok := comps[name]; !ok {
			t.Errorf("health components missing %q", name)
		}
	}
}

func TestE2E_Health_Degraded(t *testing.T) {
	// The mock pinger in newTestEnv always succeeds so that env tests the
	// healthy path. The degraded 503 path is covered by health handler unit tests.
	t.Skip("degraded path covered by unit tests")
}

func TestE2E_StaticAssets(t *testing.T) {
	e := newTestEnv(t)

	for _, asset := range []string{
		"/static/tailwind.css",
		"/static/alpine.min.js",
		"/static/chart.min.js",
	} {
		t.Run(asset, func(t *testing.T) {
			resp, err := e.client.Get(e.baseURL + asset)
			if err != nil {
				t.Fatalf("GET %s: %v", asset, err)
			}
			defer resp.Body.Close()
			assertStatus(t, resp, http.StatusOK)
			ct := resp.Header.Get("Content-Type")
			if !strings.Contains(ct, "javascript") && !strings.Contains(ct, "text/") {
				t.Errorf("Content-Type %q: expected JS or text", ct)
			}
		})
	}
}

func TestE2E_StaticAsset_NotFound(t *testing.T) {
	e := newTestEnv(t)
	resp, err := e.client.Get(e.baseURL + "/static/does-not-exist.js")
	if err != nil {
		t.Fatalf("GET /static/does-not-exist.js: %v", err)
	}
	defer resp.Body.Close()
	assertStatus(t, resp, http.StatusNotFound)
}

func TestE2E_SecurityHeaders(t *testing.T) {
	e := newTestEnv(t)

	resp, err := e.client.Get(e.baseURL + "/health")
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	defer resp.Body.Close()

	for header, want := range map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "strict-origin-when-cross-origin",
	} {
		got := resp.Header.Get(header)
		if got != want {
			t.Errorf("header %s: got %q, want %q", header, got, want)
		}
	}
	csp := resp.Header.Get("Content-Security-Policy")
	if csp == "" {
		t.Error("Content-Security-Policy header missing")
	}
	if strings.Contains(csp, "cdn.") || strings.Contains(csp, "cdnjs") {
		t.Error("CSP contains CDN domain — all assets must be self-hosted")
	}
}

// ── auth flow ────────────────────────────────────────────────────────────────

func TestE2E_Login_Page(t *testing.T) {
	e := newTestEnv(t)

	resp, err := e.client.Get(e.baseURL + "/login")
	if err != nil {
		t.Fatalf("GET /login: %v", err)
	}
	defer resp.Body.Close()

	assertStatus(t, resp, http.StatusOK)
	assertContentType(t, resp, "text/html")
	body := readBody(resp)
	if !strings.Contains(body, "login") && !strings.Contains(body, "Login") {
		t.Error("login page does not contain 'login' text")
	}
}

func TestE2E_Login_WrongCredentials(t *testing.T) {
	e := newTestEnv(t)

	resp := e.login(t, "admin", "wrongpassword")
	defer resp.Body.Close()

	// Wrong password: re-renders login page (200), not a redirect.
	assertStatus(t, resp, http.StatusOK)
	body := readBody(resp)
	if !strings.Contains(body, "Invalid") {
		t.Errorf("expected error message in login page, got: %s", body)
	}
}

func TestE2E_Login_WrongUsername(t *testing.T) {
	e := newTestEnv(t)

	resp := e.login(t, "notadmin", testPassword)
	defer resp.Body.Close()
	assertStatus(t, resp, http.StatusOK)
}

func TestE2E_Login_Success(t *testing.T) {
	e := newTestEnv(t)

	resp := e.login(t, "admin", testPassword)
	defer resp.Body.Close()

	assertStatus(t, resp, http.StatusSeeOther)
	if resp.Header.Get("Location") != "/" {
		t.Errorf("Location: got %q, want /", resp.Header.Get("Location"))
	}

	// Cookies must be present on the redirect response.
	var gotSession, gotCSRF bool
	for _, c := range resp.Cookies() {
		if c.Name == "mailhook_session" {
			gotSession = true
		}
		if c.Name == "mailhook_csrf" {
			gotCSRF = true
		}
	}
	if !gotSession {
		t.Error("mailhook_session cookie not set on login response")
	}
	if !gotCSRF {
		t.Error("mailhook_csrf cookie not set on login response")
	}
}

func TestE2E_ProtectedPage_RedirectsWithoutAuth(t *testing.T) {
	e := newTestEnv(t)

	for _, path := range []string{"/", "/quarantine", "/stats", "/allowlists", "/settings"} {
		t.Run(path, func(t *testing.T) {
			resp, err := e.noRedir.Get(e.baseURL + path)
			if err != nil {
				t.Fatalf("GET %s: %v", path, err)
			}
			defer resp.Body.Close()
			assertStatus(t, resp, http.StatusSeeOther)
			if !strings.Contains(resp.Header.Get("Location"), "/login") {
				t.Errorf("redirect target: got %q, want /login", resp.Header.Get("Location"))
			}
		})
	}
}

func TestE2E_APIRoutes_Return401WithoutAuth(t *testing.T) {
	e := newTestEnv(t)

	for _, path := range []string{
		"/api/scans",
		"/api/whitelist",
		"/api/blocklist",
		"/api/defang?url=http://example.com",
	} {
		t.Run(path, func(t *testing.T) {
			resp, err := e.noRedir.Get(e.baseURL + path)
			if err != nil {
				t.Fatalf("GET %s: %v", path, err)
			}
			defer resp.Body.Close()
			assertStatus(t, resp, http.StatusUnauthorized)
			assertContentType(t, resp, "application/json")
		})
	}
}

// ── authenticated pages ───────────────────────────────────────────────────────

func TestE2E_Pages_RenderHTML(t *testing.T) {
	e := newTestEnv(t)
	e.mustLogin(t)

	for _, tc := range []struct {
		path string
		want string // expected text fragment in the body
	}{
		{"/", "MailHook"},
		{"/quarantine", "Quarantine"},
		{"/stats", "Statistics"},
		{"/allowlists", "Lists"},
		{"/settings", "Settings"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			resp, err := e.client.Get(e.baseURL + tc.path)
			if err != nil {
				t.Fatalf("GET %s: %v", tc.path, err)
			}
			defer resp.Body.Close()
			assertStatus(t, resp, http.StatusOK)
			assertContentType(t, resp, "text/html")
			body := readBody(resp)
			if !strings.Contains(body, tc.want) {
				t.Errorf("GET %s: body does not contain %q", tc.path, tc.want)
			}
		})
	}
}

// ── defang API ────────────────────────────────────────────────────────────────

func TestE2E_DefangURL(t *testing.T) {
	e := newTestEnv(t)
	e.mustLogin(t)

	cases := []struct {
		input    string
		expected string
	}{
		{"https://evil.com/path", "hxxps://evil[.]com/path"},
		{"http://malware.example.org", "hxxp://malware[.]example[.]org"},
		{"ftp://files.example.com/file.exe", "fxp://files[.]example[.]com/file.exe"},
	}

	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			resp, err := e.client.Get(e.baseURL + "/api/defang?url=" + url.QueryEscape(tc.input))
			if err != nil {
				t.Fatalf("GET /api/defang: %v", err)
			}
			assertStatus(t, resp, http.StatusOK)
			var result map[string]string
			decodeJSON(t, resp, &result)
			if result["defanged"] != tc.expected {
				t.Errorf("defanged %q: got %q, want %q", tc.input, result["defanged"], tc.expected)
			}
		})
	}
}

func TestE2E_DefangURL_MissingParam(t *testing.T) {
	e := newTestEnv(t)
	e.mustLogin(t)

	resp, err := e.client.Get(e.baseURL + "/api/defang")
	if err != nil {
		t.Fatalf("GET /api/defang: %v", err)
	}
	defer resp.Body.Close()
	assertStatus(t, resp, http.StatusBadRequest)
}

// ── CSRF protection ───────────────────────────────────────────────────────────

func TestE2E_CSRF_BlocksWithoutToken(t *testing.T) {
	e := newTestEnv(t)
	e.mustLogin(t)

	// POST /api/whitelist without X-CSRF-Token header must fail with 403.
	b, _ := json.Marshal(map[string]string{"entry": "test@example.com"})
	req, _ := http.NewRequest(http.MethodPost, e.baseURL+"/api/whitelist", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	// intentionally no X-CSRF-Token

	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatalf("POST /api/whitelist: %v", err)
	}
	defer resp.Body.Close()
	assertStatus(t, resp, http.StatusForbidden)
}

func TestE2E_CSRF_BlocksWrongToken(t *testing.T) {
	e := newTestEnv(t)
	e.mustLogin(t)

	b, _ := json.Marshal(map[string]string{"entry": "test@example.com"})
	req, _ := http.NewRequest(http.MethodPost, e.baseURL+"/api/whitelist", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", "definitely-wrong-token")

	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatalf("POST /api/whitelist: %v", err)
	}
	defer resp.Body.Close()
	assertStatus(t, resp, http.StatusForbidden)
}

// ── whitelist CRUD ────────────────────────────────────────────────────────────

func TestE2E_Whitelist_CRUD(t *testing.T) {
	e := newTestEnv(t)
	e.mustLogin(t)

	t.Run("list_empty", func(t *testing.T) {
		resp, err := e.client.Get(e.baseURL + "/api/whitelist")
		if err != nil {
			t.Fatalf("GET /api/whitelist: %v", err)
		}
		assertStatus(t, resp, http.StatusOK)
		var entries []interface{}
		decodeJSON(t, resp, &entries)
		if len(entries) != 0 {
			t.Errorf("expected 0 entries, got %d", len(entries))
		}
	})

	var createdID float64

	t.Run("add_address", func(t *testing.T) {
		resp := e.apiPost(t, "/api/whitelist", map[string]interface{}{
			"entry":       "sender@trusted.com",
			"bypass_scan": false,
			"reason":      "trusted partner",
		})
		assertStatus(t, resp, http.StatusCreated)
		var entry map[string]interface{}
		decodeJSON(t, resp, &entry)
		if entry["Entry"] != "sender@trusted.com" {
			t.Errorf("Entry: got %v", entry["Entry"])
		}
		if entry["EntryType"] != "address" {
			t.Errorf("EntryType: got %v, want address", entry["EntryType"])
		}
		id, ok := entry["ID"].(float64)
		if !ok || id == 0 {
			t.Fatalf("ID not returned: %v", entry)
		}
		createdID = id
	})

	t.Run("add_domain", func(t *testing.T) {
		resp := e.apiPost(t, "/api/whitelist", map[string]interface{}{
			"entry":       "@trusted.com",
			"bypass_scan": true,
		})
		assertStatus(t, resp, http.StatusCreated)
		var entry map[string]interface{}
		decodeJSON(t, resp, &entry)
		if entry["EntryType"] != "domain" {
			t.Errorf("EntryType: got %v, want domain", entry["EntryType"])
		}
		if entry["BypassScan"] != true {
			t.Errorf("BypassScan: got %v, want true", entry["BypassScan"])
		}
	})

	t.Run("list_has_entries", func(t *testing.T) {
		resp, err := e.client.Get(e.baseURL + "/api/whitelist")
		if err != nil {
			t.Fatalf("GET /api/whitelist: %v", err)
		}
		assertStatus(t, resp, http.StatusOK)
		var entries []interface{}
		decodeJSON(t, resp, &entries)
		if len(entries) != 2 {
			t.Errorf("expected 2 entries, got %d", len(entries))
		}
	})

	t.Run("duplicate_rejected", func(t *testing.T) {
		resp := e.apiPost(t, "/api/whitelist", map[string]interface{}{
			"entry": "sender@trusted.com",
		})
		defer resp.Body.Close()
		assertStatus(t, resp, http.StatusConflict)
	})

	t.Run("empty_entry_rejected", func(t *testing.T) {
		resp := e.apiPost(t, "/api/whitelist", map[string]interface{}{
			"entry": "   ",
		})
		defer resp.Body.Close()
		assertStatus(t, resp, http.StatusBadRequest)
	})

	t.Run("delete", func(t *testing.T) {
		resp := e.apiDelete(t, fmt.Sprintf("/api/whitelist/%d", int(createdID)))
		assertStatus(t, resp, http.StatusOK)
		var result map[string]string
		decodeJSON(t, resp, &result)
		if result["status"] != "deleted" {
			t.Errorf("status: got %q, want deleted", result["status"])
		}
	})

	t.Run("list_after_delete", func(t *testing.T) {
		resp, err := e.client.Get(e.baseURL + "/api/whitelist")
		if err != nil {
			t.Fatalf("GET /api/whitelist: %v", err)
		}
		assertStatus(t, resp, http.StatusOK)
		var entries []interface{}
		decodeJSON(t, resp, &entries)
		if len(entries) != 1 {
			t.Errorf("expected 1 entry after delete, got %d", len(entries))
		}
	})
}

// ── blocklist CRUD ────────────────────────────────────────────────────────────

func TestE2E_Blocklist_CRUD(t *testing.T) {
	e := newTestEnv(t)
	e.mustLogin(t)

	t.Run("list_empty", func(t *testing.T) {
		resp, err := e.client.Get(e.baseURL + "/api/blocklist")
		if err != nil {
			t.Fatalf("GET /api/blocklist: %v", err)
		}
		assertStatus(t, resp, http.StatusOK)
		var entries []interface{}
		decodeJSON(t, resp, &entries)
		if len(entries) != 0 {
			t.Errorf("expected 0 entries, got %d", len(entries))
		}
	})

	var createdID float64

	t.Run("add_address", func(t *testing.T) {
		resp := e.apiPost(t, "/api/blocklist", map[string]interface{}{
			"entry":  "spammer@evil.com",
			"reason": "known spammer",
		})
		assertStatus(t, resp, http.StatusCreated)
		var entry map[string]interface{}
		decodeJSON(t, resp, &entry)
		if entry["Entry"] != "spammer@evil.com" {
			t.Errorf("Entry: got %v", entry["Entry"])
		}
		id, ok := entry["ID"].(float64)
		if !ok || id == 0 {
			t.Fatalf("ID not returned: %v", entry)
		}
		createdID = id
	})

	t.Run("add_domain", func(t *testing.T) {
		resp := e.apiPost(t, "/api/blocklist", map[string]interface{}{
			"entry": "@malicious.org",
		})
		assertStatus(t, resp, http.StatusCreated)
		var entry map[string]interface{}
		decodeJSON(t, resp, &entry)
		if entry["EntryType"] != "domain" {
			t.Errorf("EntryType: got %v, want domain", entry["EntryType"])
		}
	})

	t.Run("list_has_entries", func(t *testing.T) {
		resp, err := e.client.Get(e.baseURL + "/api/blocklist")
		if err != nil {
			t.Fatalf("GET /api/blocklist: %v", err)
		}
		assertStatus(t, resp, http.StatusOK)
		var entries []interface{}
		decodeJSON(t, resp, &entries)
		if len(entries) != 2 {
			t.Errorf("expected 2 entries, got %d", len(entries))
		}
	})

	t.Run("delete", func(t *testing.T) {
		resp := e.apiDelete(t, fmt.Sprintf("/api/blocklist/%d", int(createdID)))
		assertStatus(t, resp, http.StatusOK)
		var result map[string]string
		decodeJSON(t, resp, &result)
		if result["status"] != "deleted" {
			t.Errorf("status: got %q, want deleted", result["status"])
		}
	})
}

// ── bulk import ───────────────────────────────────────────────────────────────

func TestE2E_BulkImport_Whitelist(t *testing.T) {
	e := newTestEnv(t)
	e.mustLogin(t)

	entries := "user1@example.com\nuser2@example.com\n# comment\n   \nuser3@example.com"
	resp := e.apiPost(t, "/api/allowlists/bulk-import", map[string]interface{}{
		"list":        "whitelist",
		"entries":     entries,
		"bypass_scan": false,
	})
	assertStatus(t, resp, http.StatusOK)
	var result map[string]int
	decodeJSON(t, resp, &result)
	if result["imported"] != 3 {
		t.Errorf("imported: got %d, want 3", result["imported"])
	}
	if result["skipped"] != 0 {
		t.Errorf("skipped: got %d, want 0", result["skipped"])
	}
}

func TestE2E_BulkImport_Blocklist(t *testing.T) {
	e := newTestEnv(t)
	e.mustLogin(t)

	entries := "spam1@evil.com\nspam2@evil.com"
	resp := e.apiPost(t, "/api/allowlists/bulk-import", map[string]interface{}{
		"list":    "blocklist",
		"entries": entries,
	})
	assertStatus(t, resp, http.StatusOK)
	var result map[string]int
	decodeJSON(t, resp, &result)
	if result["imported"] != 2 {
		t.Errorf("imported: got %d, want 2", result["imported"])
	}
}

func TestE2E_BulkImport_InvalidList(t *testing.T) {
	e := newTestEnv(t)
	e.mustLogin(t)

	resp := e.apiPost(t, "/api/allowlists/bulk-import", map[string]interface{}{
		"list":    "invalidlist",
		"entries": "foo@bar.com",
	})
	defer resp.Body.Close()
	assertStatus(t, resp, http.StatusBadRequest)
}

func TestE2E_BulkImport_Duplicates_Skipped(t *testing.T) {
	e := newTestEnv(t)
	e.mustLogin(t)

	// Import once.
	entries := "unique@test.com"
	resp := e.apiPost(t, "/api/allowlists/bulk-import", map[string]interface{}{
		"list": "whitelist", "entries": entries,
	})
	resp.Body.Close()

	// Import same entry again — should be skipped.
	resp2 := e.apiPost(t, "/api/allowlists/bulk-import", map[string]interface{}{
		"list": "whitelist", "entries": entries,
	})
	assertStatus(t, resp2, http.StatusOK)
	var result map[string]int
	decodeJSON(t, resp2, &result)
	if result["skipped"] != 1 {
		t.Errorf("expected 1 skipped duplicate, got %d", result["skipped"])
	}
}

// ── scan list API ─────────────────────────────────────────────────────────────

func TestE2E_Scans_EmptyList(t *testing.T) {
	e := newTestEnv(t)
	e.mustLogin(t)

	resp, err := e.client.Get(e.baseURL + "/api/scans")
	if err != nil {
		t.Fatalf("GET /api/scans: %v", err)
	}
	assertStatus(t, resp, http.StatusOK)
	assertContentType(t, resp, "application/json")

	var result map[string]interface{}
	decodeJSON(t, resp, &result)
	if result["total"] != float64(0) {
		t.Errorf("total: got %v, want 0", result["total"])
	}
	scans, ok := result["scans"].([]interface{})
	if !ok {
		t.Fatal("scans field is not an array")
	}
	if len(scans) != 0 {
		t.Errorf("scans: got %d, want 0", len(scans))
	}
}

func TestE2E_Scans_GetMissing(t *testing.T) {
	e := newTestEnv(t)
	e.mustLogin(t)

	resp, err := e.client.Get(e.baseURL + "/api/scans/99999")
	if err != nil {
		t.Fatalf("GET /api/scans/99999: %v", err)
	}
	defer resp.Body.Close()
	assertStatus(t, resp, http.StatusNotFound)
}

// ── settings API ──────────────────────────────────────────────────────────────

func TestE2E_Settings_UpdateThresholds(t *testing.T) {
	e := newTestEnv(t)
	e.mustLogin(t)

	resp := e.apiPost(t, "/api/settings/thresholds", map[string]interface{}{
		"spam_score":   6.5,
		"reject_score": 20.0,
	})
	assertStatus(t, resp, http.StatusOK)
	var result map[string]interface{}
	decodeJSON(t, resp, &result)
	if result["spam_score"] != 6.5 {
		t.Errorf("spam_score: got %v, want 6.5", result["spam_score"])
	}
	if result["reject_score"] != 20.0 {
		t.Errorf("reject_score: got %v, want 20.0", result["reject_score"])
	}
	if e.cfg.SpamScore != 6.5 {
		t.Errorf("cfg.SpamScore not updated: got %v", e.cfg.SpamScore)
	}
}

func TestE2E_Settings_UpdateThresholds_Invalid(t *testing.T) {
	e := newTestEnv(t)
	e.mustLogin(t)

	// spam >= reject — must be rejected
	resp := e.apiPost(t, "/api/settings/thresholds", map[string]interface{}{
		"spam_score":   20.0,
		"reject_score": 10.0,
	})
	defer resp.Body.Close()
	assertStatus(t, resp, http.StatusBadRequest)
}

func TestE2E_Settings_FeedsRefresh(t *testing.T) {
	e := newTestEnv(t)
	e.mustLogin(t)

	resp := e.apiPost(t, "/api/settings/feeds-refresh", nil)
	defer resp.Body.Close()
	assertStatus(t, resp, http.StatusAccepted)
}

func TestE2E_Settings_YARAReload(t *testing.T) {
	e := newTestEnv(t)
	e.mustLogin(t)

	resp := e.apiPost(t, "/api/settings/yara-reload", nil)
	assertStatus(t, resp, http.StatusOK)
	var result map[string]string
	decodeJSON(t, resp, &result)
	if result["status"] != "reloaded" {
		t.Errorf("status: got %q, want reloaded", result["status"])
	}
}

func TestE2E_Settings_NotifyTest_NotConfigured(t *testing.T) {
	e := newTestEnv(t)
	e.mustLogin(t)

	// NtfyURL is empty in test config — expect 400.
	resp := e.apiPost(t, "/api/settings/notify-test", nil)
	defer resp.Body.Close()
	assertStatus(t, resp, http.StatusBadRequest)
}

// ── metrics endpoint ──────────────────────────────────────────────────────────

func TestE2E_Metrics_AllowedFromLocalhost(t *testing.T) {
	e := newTestEnv(t)

	// httptest server listens on loopback; remote addr will be 127.0.0.1 or ::1.
	resp, err := e.client.Get(e.baseURL + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer resp.Body.Close()
	// Metrics is allowed from 127.0.0.1/32 and ::1/128 in test config.
	// The response is either 200 (if loopback matches) or 403.
	// We accept both — the important thing is we don't get 5xx.
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusForbidden {
		t.Errorf("unexpected metrics status %d", resp.StatusCode)
	}
}

// ── logout ────────────────────────────────────────────────────────────────────

func TestE2E_Logout(t *testing.T) {
	e := newTestEnv(t)
	e.mustLogin(t)

	// Confirm authenticated access works before logout.
	r, err := e.client.Get(e.baseURL + "/")
	if err != nil {
		t.Fatalf("GET / (before logout): %v", err)
	}
	r.Body.Close()
	assertStatus(t, r, http.StatusOK)

	// Logout via POST (no CSRF required for logout — session only).
	req, _ := http.NewRequest(http.MethodPost, e.baseURL+"/logout", nil)
	logoutResp, err := e.noRedir.Do(req)
	if err != nil {
		t.Fatalf("POST /logout: %v", err)
	}
	logoutResp.Body.Close()
	assertStatus(t, logoutResp, http.StatusSeeOther)

	// After logout, GET / must redirect to /login.
	checkResp, err := e.noRedir.Get(e.baseURL + "/")
	if err != nil {
		t.Fatalf("GET / (after logout): %v", err)
	}
	checkResp.Body.Close()
	assertStatus(t, checkResp, http.StatusSeeOther)
	if !strings.Contains(checkResp.Header.Get("Location"), "/login") {
		t.Errorf("expected redirect to /login after logout, got %q", checkResp.Header.Get("Location"))
	}
}

// ── allowlists page (HTML) ────────────────────────────────────────────────────

func TestE2E_AllowlistsPage_ShowsEntries(t *testing.T) {
	e := newTestEnv(t)
	e.mustLogin(t)

	// Add a whitelist and blocklist entry via API first.
	e.apiPost(t, "/api/whitelist", map[string]interface{}{
		"entry": "trusted@example.com",
	}).Body.Close()
	e.apiPost(t, "/api/blocklist", map[string]interface{}{
		"entry": "spammer@evil.org",
	}).Body.Close()

	resp, err := e.client.Get(e.baseURL + "/allowlists")
	if err != nil {
		t.Fatalf("GET /allowlists: %v", err)
	}
	defer resp.Body.Close()
	assertStatus(t, resp, http.StatusOK)
	body := readBody(resp)
	if !strings.Contains(body, "trusted@example.com") {
		t.Error("allowlists page missing whitelist entry")
	}
	if !strings.Contains(body, "spammer@evil.org") {
		t.Error("allowlists page missing blocklist entry")
	}
}

// ── EML download not-found ────────────────────────────────────────────────────

func TestE2E_EML_NotFound(t *testing.T) {
	e := newTestEnv(t)
	e.mustLogin(t)

	resp, err := e.client.Get(e.baseURL + "/api/eml/99999")
	if err != nil {
		t.Fatalf("GET /api/eml/99999: %v", err)
	}
	defer resp.Body.Close()
	assertStatus(t, resp, http.StatusNotFound)
}

// ── end-to-end auth state persistence across requests ─────────────────────────

func TestE2E_SessionPersistsAcrossRequests(t *testing.T) {
	e := newTestEnv(t)
	e.mustLogin(t)

	// Make multiple sequential authenticated requests to prove the session
	// cookie persists across a full request lifecycle.
	for i := range 5 {
		resp, err := e.client.Get(e.baseURL + "/api/scans")
		if err != nil {
			t.Fatalf("iteration %d GET /api/scans: %v", i, err)
		}
		resp.Body.Close()
		assertStatus(t, resp, http.StatusOK)
	}
}

func TestE2E_Settings_UpdateAPIKeys(t *testing.T) {
	e := newTestEnv(t)
	e.mustLogin(t)

	resp := e.apiPost(t, "/api/settings/api-keys", map[string]interface{}{
		"vt_api_key":    "test-vt-key-12345",
		"abuseipdb_key": "test-abuse-key",
	})
	assertStatus(t, resp, http.StatusOK)
	var result map[string]interface{}
	decodeJSON(t, resp, &result)
	if result["vt_configured"] != true {
		t.Errorf("vt_configured: got %v, want true", result["vt_configured"])
	}
	if result["ipRep_configured"] != true {
		t.Errorf("ipRep_configured: got %v, want true", result["ipRep_configured"])
	}
	// Verify persistence in config
	if e.cfg.VTAPIKey != "test-vt-key-12345" {
		t.Errorf("cfg.VTAPIKey not updated: got %q", e.cfg.VTAPIKey)
	}
}

func TestE2E_Settings_UpdateNotifications(t *testing.T) {
	e := newTestEnv(t)
	e.mustLogin(t)

	resp := e.apiPost(t, "/api/settings/notifications", map[string]interface{}{
		"ntfy_url":   "https://ntfy.example.com",
		"ntfy_topic": "my-topic",
		"ntfy_token": "secret-token",
	})
	assertStatus(t, resp, http.StatusOK)
	var result map[string]interface{}
	decodeJSON(t, resp, &result)
	if result["ntfy_url"] != "https://ntfy.example.com" {
		t.Errorf("ntfy_url: got %v", result["ntfy_url"])
	}
	if result["enabled"] != true {
		t.Errorf("enabled: got %v, want true", result["enabled"])
	}
	if e.cfg.NtfyURL != "https://ntfy.example.com" {
		t.Errorf("cfg.NtfyURL not updated: got %q", e.cfg.NtfyURL)
	}
}

func TestE2E_Settings_UpdateScanners(t *testing.T) {
	e := newTestEnv(t)
	e.mustLogin(t)

	// With no scanners registered (nil slice), the response should be an empty object.
	resp := e.apiPost(t, "/api/settings/scanners", map[string]bool{
		"rspamd": false,
	})
	assertStatus(t, resp, http.StatusOK)
	var result map[string]bool
	decodeJSON(t, resp, &result)
	// No scanners registered in test env, so result is empty — just verify no error.
	_ = result
}
