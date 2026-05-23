package handlers

import (
	"log/slog"
	"net/http"

	"golang.org/x/crypto/bcrypt"

	"github.com/izm1chael/mailhook/auth"
	"github.com/izm1chael/mailhook/config"
	"github.com/izm1chael/mailhook/web"
)

// AuthHandler handles login and logout.
type AuthHandler struct {
	cfg         *config.Config
	sessions    *auth.Store
	rateLimiter *auth.LoginRateLimiter
	middleware  *auth.Middleware
	log         *slog.Logger
}

// NewAuthHandler creates an AuthHandler.
func NewAuthHandler(cfg *config.Config, sessions *auth.Store, rl *auth.LoginRateLimiter, middleware *auth.Middleware, log *slog.Logger) *AuthHandler {
	return &AuthHandler{cfg: cfg, sessions: sessions, rateLimiter: rl, middleware: middleware, log: log}
}

// GetLogin renders the login form.
func (h *AuthHandler) GetLogin(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.sessions.Get(sessionToken(r)); ok {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	web.Render(w, r, "login.html", map[string]interface{}{
		"Error": r.URL.Query().Get("error"),
	})
}

// PostLogin processes the login form submission.
func (h *AuthHandler) PostLogin(w http.ResponseWriter, r *http.Request) {
	ip := h.middleware.ClientIP(r)

	allowed, retryAfter := h.rateLimiter.Allow(ip)
	if !allowed {
		h.log.Warn("login rate limit exceeded", "ip", ip, "retry_after", retryAfter)
		web.Render(w, r, "login.html", map[string]interface{}{
			"Error": "Too many failed attempts. Please try again later.",
		})
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	// Always run bcrypt to equalize response timing regardless of whether the
	// username matches — prevents username enumeration via timing oracle.
	targetHash := h.cfg.GetAdminPasswordBcrypt()
	if username != h.cfg.AdminUser {
		// Use a dummy hash so bcrypt work happens regardless; discard the result.
		targetHash = "$2a$12$invalidusernameXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" // nosemgrep: generic.secrets.security.detected-bcrypt-hash.detected-bcrypt-hash
	}
	if err := bcrypt.CompareHashAndPassword(
		[]byte(targetHash), []byte(password)); err != nil || username != h.cfg.AdminUser {
		h.rateLimiter.Record(ip)
		h.log.Warn("failed login attempt", "ip", ip, "username", username)
		web.Render(w, r, "login.html", map[string]interface{}{"Error": "Invalid credentials"})
		return
	}

	token := h.sessions.Create(username, ip)
	h.middleware.SetSessionCookie(w, token, int(h.sessions.TTL().Seconds()))

	// Rotate CSRF token on login
	h.middleware.SetCSRFCookie(w)

	h.log.Info("login successful", "ip", ip, "username", username)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// PostLogout destroys the session and clears cookies.
func (h *AuthHandler) PostLogout(w http.ResponseWriter, r *http.Request) {
	if token := sessionToken(r); token != "" {
		h.sessions.Delete(token)
	}
	h.middleware.SetSessionCookie(w, "", -1)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// sessionToken reads the session cookie value from the request.
func sessionToken(r *http.Request) string {
	c, err := r.Cookie("mailhook_session")
	if err != nil {
		return ""
	}
	return c.Value
}
