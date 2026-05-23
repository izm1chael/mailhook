package web

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/json"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"sync"

	"github.com/izm1chael/mailhook/metrics"
)

type contextKey string

const nonceContextKey contextKey = "csp-nonce"

// NonceFromContext returns the CSP nonce for the current request.
func NonceFromContext(r *http.Request) string {
	if v, ok := r.Context().Value(nonceContextKey).(string); ok {
		return v
	}
	return ""
}

func generateNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

//go:embed templates
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

// StaticHandler returns an HTTP handler that serves embedded static assets under /static/.
func StaticHandler() http.Handler {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic("static embed sub: " + err.Error())
	}
	return http.FileServer(http.FS(sub))
}

// Templates holds compiled HTML templates for all pages.
var Templates *template.Template

// InitTemplates parses all templates from the embedded FS.
func InitTemplates() error {
	t, err := template.New("").Funcs(templateFuncs()).ParseFS(templateFS, "templates/*.html", "templates/partials/*.html")
	if err != nil {
		return err
	}
	Templates = t
	return nil
}

// SSEHub manages Server-Sent Events subscribers.
type SSEHub struct {
	mu      sync.Mutex
	clients map[chan []byte]struct{}
}

// NewSSEHub creates a hub.
func NewSSEHub() *SSEHub {
	return &SSEHub{clients: make(map[chan []byte]struct{})}
}

// Subscribe returns a channel that receives SSE event data.
func (h *SSEHub) Subscribe() chan []byte {
	ch := make(chan []byte, 16)
	h.mu.Lock()
	h.clients[ch] = struct{}{}
	h.mu.Unlock()
	metrics.SSEClients.Inc()
	return ch
}

// Unsubscribe removes the channel and closes it.
func (h *SSEHub) Unsubscribe(ch chan []byte) {
	h.mu.Lock()
	delete(h.clients, ch)
	h.mu.Unlock()
	close(ch)
	metrics.SSEClients.Dec()
}

// Broadcast sends data to all connected SSE clients.
// Non-blocking: slow clients are skipped to prevent back-pressure.
func (h *SSEHub) Broadcast(data []byte) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.clients {
		select {
		case ch <- data:
		default:
			// Drop the message for slow clients — dashboard will catch up via polling
		}
	}
}

// ConnectedClients returns the current SSE subscriber count.
func (h *SSEHub) ConnectedClients() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.clients)
}

// Recovery is a middleware that catches panics in HTTP handlers, logs them,
// and returns a 500 response so the server keeps running.
func Recovery(log interface {
	Error(msg string, args ...any)
}, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				log.Error("handler panic", "panic", v, "path", r.URL.Path)
				http.Error(w, "internal server error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// SecurityHeaders adds defensive HTTP response headers to all responses.
// A per-request CSP nonce is generated and stored in the request context;
// use NonceFromContext(r) to retrieve it in handlers and pass to templates.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonce, err := generateNonce()
		if err != nil {
			slog.Error("nonce generation failed", "err", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		ctx := context.WithValue(r.Context(), nonceContextKey, nonce)
		r = r.WithContext(ctx)

		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		// HSTS — only effective over HTTPS; include on all responses so browsers
		// remember to use HTTPS for all future requests.
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		// Nonce-based CSP: 'unsafe-inline' and 'unsafe-eval' removed.
		// Alpine.js is served as the @alpinejs/csp build which replaces Function()
		// evaluation with safe expression parsing — no 'unsafe-eval' required.
		nonceAttr := "'nonce-" + nonce + "'"
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; "+
				"script-src 'self' "+nonceAttr+"; "+
				"style-src 'self' "+nonceAttr+"; "+
				"img-src 'self' data:; "+
				"connect-src 'self'; "+
				"frame-src 'self'; "+
				"font-src 'self';")
		next.ServeHTTP(w, r)
	})
}

// templateFuncs returns custom template functions available in all templates.
func templateFuncs() template.FuncMap {
	return template.FuncMap{
		"add": func(a, b int) int { return a + b },
		"sub": func(a, b int) int { return a - b },
		// toJSON marshals v to a JSON literal safe for embedding in Alpine x-data expressions.
		// json.Marshal produces a fully-escaped JSON value (quotes and backslashes are
		// escaped), so the resulting template.JS cannot break out of a JS string context.
		"toJSON": func(v any) (template.JS, error) {
			b, err := json.Marshal(v)
			// nosemgrep: go.lang.security.audit.xss.template-html-does-not-escape.unsafe-template-type
			return template.JS(b), err // #nosec G203 -- json.Marshal output is fully escaped; cannot break out of a JS string context
		},
	}
}

// Render executes a named template and writes to w.
// It injects the per-request CSP nonce (from the security-headers middleware) into
// the template data map so templates can emit nonce="{{.Nonce}}" on inline scripts/styles.
// On error it writes a plain 500 page.
func Render(w http.ResponseWriter, r *http.Request, name string, data interface{}) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if m, ok := data.(map[string]interface{}); ok {
		m["Nonce"] = NonceFromContext(r)
	}
	if err := Templates.ExecuteTemplate(w, name, data); err != nil {
		http.Error(w, "template error: "+err.Error(), http.StatusInternalServerError)
	}
}
