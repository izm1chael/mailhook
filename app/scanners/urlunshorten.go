package scanners

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/izm1chael/mailhook/config"
	"github.com/izm1chael/mailhook/db"
	"github.com/izm1chael/mailhook/pipeline"
	"github.com/izm1chael/mailhook/util"
	"golang.org/x/time/rate"
)

// URLUnshorten follows HTTP redirect chains for each URL found in an email,
// applies SSRF protection, then scans the resolved final URL against threat feeds.
// It runs after urlcheck so it only processes URLs that required redirect resolution.
type URLUnshorten struct {
	mu            sync.RWMutex
	enabled       bool
	feeds         feedManager
	client        *http.Client
	limiter        *rate.Limiter
	maxHops       int
	perURLTO      time.Duration
	log           *slog.Logger
	// ssrfBlocked is the SSRF guard hook. It is swappable for testing.
	ssrfBlocked   func(hostname string) bool
}

// newSSRFSafeHTTPClient returns an HTTP client whose DialContext resolves each
// hostname once, validates the IP is publicly routable, then dials the resolved
// address directly — eliminating the TOCTOU window between an SSRF pre-check
// and the actual TCP connection.
func newSSRFSafeHTTPClient(timeout time.Duration) *http.Client {
	dialer := &net.Dialer{}
	return &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			DisableKeepAlives:     true,
			ResponseHeaderTimeout: timeout,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				host, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, fmt.Errorf("ssrf: invalid addr %q: %w", addr, err)
				}
				ips, err := net.LookupHost(host)
				if err != nil || len(ips) == 0 {
					return nil, fmt.Errorf("ssrf: cannot resolve %q: %w", host, err)
				}
				ip := net.ParseIP(ips[0])
				if ip == nil || !util.IsPublicIP(ip) {
					return nil, fmt.Errorf("ssrf: %q resolves to non-public address %s", host, ips[0])
				}
				return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0], port))
			},
		},
	}
}

// NewURLUnshorten creates a URLUnshorten scanner.
// The HTTP client is configured to never auto-follow redirects so the scanner
// controls each hop explicitly for SSRF validation.
func NewURLUnshorten(feeds feedManager, cfg *config.Config, log *slog.Logger) *URLUnshorten {
	u := &URLUnshorten{
		enabled:  cfg.URLUnshortenEnabled,
		feeds:    feeds,
		client:   newSSRFSafeHTTPClient(cfg.URLUnshortenPerURLTimeout),
		limiter:  rate.NewLimiter(rate.Limit(cfg.URLUnshortenRateLimit), cfg.URLUnshortenRateBurst),
		maxHops:  cfg.URLUnshortenMaxHops,
		perURLTO: cfg.URLUnshortenPerURLTimeout,
		log:      log,
	}
	u.ssrfBlocked = u.isSSRFTarget
	return u
}

// SetHTTPClient replaces the scanner's HTTP client. Used in tests to inject a
// client that allows loopback connections (bypassing the SSRF guard).
func (u *URLUnshorten) SetHTTPClient(c *http.Client) { u.client = c }

func (u *URLUnshorten) Name() string { return "urlunshorten" }

// SetEnabled enables or disables the scanner at runtime.
func (u *URLUnshorten) SetEnabled(v bool) { u.mu.Lock(); u.enabled = v; u.mu.Unlock() }

// IsEnabled reports whether the scanner is currently enabled.
func (u *URLUnshorten) IsEnabled() bool { u.mu.RLock(); defer u.mu.RUnlock(); return u.enabled }

// Scan follows redirect chains for each URL in the email and checks the resolved
// destination against threat feeds. Returns malicious if any resolved URL matches a feed.
func (u *URLUnshorten) Scan(ctx context.Context, email *pipeline.Email) pipeline.ScanResult {
	u.mu.RLock()
	enabled := u.enabled
	u.mu.RUnlock()
	if !enabled {
		return pipeline.ScanResult{Scanner: u.Name(), Verdict: "skip", Detail: "disabled"}
	}
	if len(email.URLs) == 0 {
		return pipeline.ScanResult{Scanner: u.Name(), Verdict: "clean"}
	}

	var hits []db.ResolvedURLHit
	var malicious bool

	for _, rawURL := range email.URLs {
		if !u.limiter.Allow() {
			u.log.Debug("urlunshorten: rate limit reached, skipping URL", "url", rawURL)
			continue
		}

		finalURL, hops, blocked, err := u.followRedirects(ctx, rawURL)
		if err != nil {
			u.log.Debug("urlunshorten: redirect follow error", "url", rawURL, "err", err)
			continue
		}

		// If there were no redirects and no SSRF block, urlcheck already scanned the original URL.
		if hops == 0 && !blocked {
			continue
		}

		hit := db.ResolvedURLHit{
			OriginalURL: rawURL,
			ResolvedURL: finalURL,
			Hops:        hops,
			Blocked:     blocked,
		}

		if !blocked {
			if feed, threatType, ok := u.feeds.LookupURL(finalURL); ok {
				hit.Feed = feed
				hit.ThreatType = threatType
				malicious = true
			}
		}

		hits = append(hits, hit)
	}

	if len(hits) == 0 {
		return pipeline.ScanResult{Scanner: u.Name(), Verdict: "clean"}
	}

	matchData, _ := json.Marshal(hits)

	if malicious {
		var malURLs []string
		for _, h := range hits {
			if h.Feed != "" {
				malURLs = append(malURLs, h.ResolvedURL)
			}
		}
		detail := strings.Join(malURLs, ", ")
		if len(detail) > 500 {
			detail = detail[:500] + "…"
		}
		return pipeline.ScanResult{
			Scanner: u.Name(),
			Verdict: "malicious",
			Detail:  detail,
			Matches: matchData,
		}
	}

	return pipeline.ScanResult{
		Scanner: u.Name(),
		Verdict: "clean",
		Matches: matchData,
	}
}

// followRedirects manually follows HTTP redirect chains up to maxHops.
// It resolves each redirect target's hostname to an IP and rejects private
// addresses to prevent SSRF. Only HEAD requests are made; response bodies
// are never read.
//
// IPv6 destinations are treated as non-public (blocked) because util.IsPublicIP
// only validates IPv4. This is the safe default.
func (u *URLUnshorten) followRedirects(ctx context.Context, rawURL string) (finalURL string, hops int, blocked bool, err error) {
	// Guard the initial URL before making any request — the loop below only
	// guards redirect *targets*, leaving the first hop unprotected otherwise.
	if parsed, parseErr := url.Parse(rawURL); parseErr == nil {
		if h := parsed.Hostname(); h != "" && u.ssrfBlocked(h) {
			u.log.Warn("urlunshorten: SSRF initial URL blocked", "url", rawURL)
			return rawURL, 0, true, nil
		}
	}
	current := rawURL

	for i := 0; i < u.maxHops; i++ {
		hopCtx, cancel := context.WithTimeout(ctx, u.perURLTO)
		req, reqErr := http.NewRequestWithContext(hopCtx, http.MethodHead, current, http.NoBody)
		if reqErr != nil {
			cancel()
			return current, hops, false, reqErr
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; MailHook-URLUnshorten/1.0)")

		resp, doErr := u.client.Do(req)
		cancel()
		if doErr != nil {
			return current, hops, false, doErr
		}
		resp.Body.Close()

		if resp.StatusCode < 300 || resp.StatusCode >= 400 {
			// Not a redirect — this is the final destination.
			return current, hops, false, nil
		}

		loc := resp.Header.Get("Location")
		if loc == "" {
			return current, hops, false, nil
		}

		// Resolve relative redirect against the current URL.
		base, parseErr := url.Parse(current)
		if parseErr != nil {
			return current, hops, false, parseErr
		}
		target, parseErr := url.Parse(loc)
		if parseErr != nil {
			return current, hops, false, parseErr
		}
		resolved := base.ResolveReference(target)

		// SSRF guard: resolve the target hostname to IP and reject private ranges.
		if ssrfBlocked := u.ssrfBlocked(resolved.Hostname()); ssrfBlocked {
			u.log.Warn("urlunshorten: SSRF redirect blocked", "original", rawURL, "target", resolved.String())
			return current, hops, true, nil
		}

		current = resolved.String()
		hops++
	}

	return current, hops, false, nil
}

// isSSRFTarget resolves hostname to IPs and returns true if any resolved IP
// is not publicly routable (private, loopback, link-local, etc.).
func (u *URLUnshorten) isSSRFTarget(hostname string) bool {
	ips, err := net.LookupHost(hostname)
	if err != nil {
		// Resolution failure: treat as blocked to be safe.
		return true
	}
	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}
		if !util.IsPublicIP(ip) {
			return true
		}
	}
	return false
}
