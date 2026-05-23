package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"strings"
)

const (
	sessionCookieName = "mailhook_session"
	csrfCookieName    = "mailhook_csrf"
	csrfHeaderName    = "X-CSRF-Token"
	csrfFormField     = "_csrf"
)

type contextKey string

const sessionContextKey contextKey = "session"

// Middleware wraps http.Handlers with session and CSRF protection.
type Middleware struct {
	store          *Store
	trustedProxies []*net.IPNet
	csrfSecret     []byte
	secureCookies  bool // set Secure flag on cookies; false only for local HTTP dev
}

// NewMiddleware creates a Middleware backed by the given session store.
// trustedCIDRs lists reverse-proxy CIDR ranges whose X-Forwarded-For headers are
// trusted; an empty list means all XFF headers are ignored (safe default for
// direct-to-internet deployments). csrfSecret is the HMAC-SHA256 key used to sign
// CSRF tokens — callers must supply a durable, random key so tokens survive restarts.
// secureCookies controls the Secure attribute on all cookies set by this middleware;
// pass false only when running behind plain HTTP for local development.
func NewMiddleware(store *Store, trustedCIDRs []string, csrfSecret []byte, secureCookies bool) *Middleware {
	m := &Middleware{store: store, csrfSecret: csrfSecret, secureCookies: secureCookies}
	for _, cidr := range trustedCIDRs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err == nil {
			m.trustedProxies = append(m.trustedProxies, ipNet)
		}
	}
	return m
}

// Require wraps a handler to require a valid session.
// API paths (/api/*) return 401 JSON on failure; page paths redirect to /login.
func (m *Middleware) Require(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(sessionCookieName)
		if err != nil || cookie.Value == "" {
			m.unauthorized(w, r)
			return
		}
		sess, ok := m.store.Get(cookie.Value)
		if !ok {
			// Clear stale cookie — must include HttpOnly and Secure to match original flags
			http.SetCookie(w, &http.Cookie{ // nosemgrep: go.lang.security.audit.net.cookie-missing-secure.cookie-missing-secure
				Name:     sessionCookieName,
				Value:    "",
				Path:     "/",
				MaxAge:   -1,
				HttpOnly: true,
				Secure:   m.secureCookies,
				SameSite: http.SameSiteStrictMode,
			})
			m.unauthorized(w, r)
			return
		}
		m.store.Touch(cookie.Value)
		ctx := context.WithValue(r.Context(), sessionContextKey, sess)
		next(w, r.WithContext(ctx))
	}
}

// CSRF verifies the double-submit CSRF token. The cookie value is a signed
// "nonce.HMAC" pair — the HMAC prevents cookie-tossing attacks where an attacker
// with subdomain XSS injects a forged cookie they also control the header value for.
func (m *Middleware) CSRF(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get(csrfHeaderName)
		if token == "" {
			token = r.FormValue(csrfFormField)
		}
		cookie, err := r.Cookie(csrfCookieName)
		if err != nil {
			m.csrfDenied(w)
			return
		}
		parts := strings.SplitN(cookie.Value, ".", 2)
		if len(parts) != 2 {
			m.csrfDenied(w)
			return
		}
		nonceBytes, err := hex.DecodeString(parts[0])
		if err != nil {
			m.csrfDenied(w)
			return
		}
		mac := hmac.New(sha256.New, m.csrfSecret)
		mac.Write(nonceBytes)
		expectedSig := hex.EncodeToString(mac.Sum(nil))
		// Verify cookie signature first — a forged cookie fails here.
		if !hmac.Equal([]byte(expectedSig), []byte(parts[1])) {
			m.csrfDenied(w)
			return
		}
		// Verify the submitted token matches the nonce in the signed cookie.
		if !hmac.Equal([]byte(token), []byte(parts[0])) {
			m.csrfDenied(w)
			return
		}
		next(w, r)
	}
}

// SetCSRFCookie generates a signed CSRF token, stores "nonce.HMAC" in an HttpOnly
// cookie, and returns only the nonce to be embedded in the page's
// <meta name="csrf-token">. JS reads the meta tag (same-origin only) and sends the
// nonce as X-CSRF-Token — it never needs to read the cookie directly.
func (m *Middleware) SetCSRFCookie(w http.ResponseWriter) string {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		panic("auth: crypto/rand unavailable: " + err.Error())
	}
	nonceHex := hex.EncodeToString(nonce)
	mac := hmac.New(sha256.New, m.csrfSecret)
	mac.Write(nonce)
	sig := hex.EncodeToString(mac.Sum(nil))
	http.SetCookie(w, &http.Cookie{ // nosemgrep: go.lang.security.audit.net.cookie-missing-secure.cookie-missing-secure
		Name:     csrfCookieName,
		Value:    nonceHex + "." + sig,
		Path:     "/",
		HttpOnly: true,
		Secure:   m.secureCookies,
		SameSite: http.SameSiteStrictMode,
	})
	return nonceHex
}

// SetSessionCookie sets the session cookie for the given token.
// Secure follows the middleware's secureCookies setting — false only for local HTTP dev
// when MAILHOOK_INSECURE_COOKIES=true is set.
func (m *Middleware) SetSessionCookie(w http.ResponseWriter, token string, maxAge int) {
	http.SetCookie(w, &http.Cookie{ // nosemgrep: go.lang.security.audit.net.cookie-missing-secure.cookie-missing-secure
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   m.secureCookies,
		SameSite: http.SameSiteStrictMode,
	})
}

// SessionFromContext returns the authenticated session from the request context.
func SessionFromContext(r *http.Request) *Session {
	s, _ := r.Context().Value(sessionContextKey).(*Session)
	return s
}

// ClientIP extracts the real client IP. X-Forwarded-For is only trusted if the
// direct TCP peer (r.RemoteAddr) falls within a configured trusted proxy CIDR.
// With no trusted proxies configured, the raw RemoteAddr is always used.
// XFF is parsed right-to-left: skip trusted proxy entries and return the first
// untrusted IP — this prevents clients spoofing the left-most XFF entry.
func (m *Middleware) ClientIP(r *http.Request) string {
	remoteIP := extractRemoteIP(r.RemoteAddr)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" && m.isTrustedProxy(remoteIP) {
		parts := strings.Split(xff, ",")
		for i := len(parts) - 1; i >= 0; i-- {
			ip := strings.TrimSpace(parts[i])
			if !m.isTrustedProxy(ip) {
				return ip
			}
		}
		// All entries in the chain are trusted proxies — fall back to left-most.
		return strings.TrimSpace(parts[0])
	}
	return remoteIP
}

func (m *Middleware) isTrustedProxy(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, cidr := range m.trustedProxies {
		if cidr.Contains(parsed) {
			return true
		}
	}
	return false
}

func extractRemoteIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}

func (m *Middleware) unauthorized(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"unauthorized"}`)) // nosemgrep: go.lang.security.audit.xss.no-direct-write-to-responsewriter.no-direct-write-to-responsewriter
		return
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (m *Middleware) csrfDenied(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	w.Write([]byte(`{"error":"CSRF validation failed"}`)) // nosemgrep: go.lang.security.audit.xss.no-direct-write-to-responsewriter.no-direct-write-to-responsewriter
}
