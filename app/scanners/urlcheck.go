package scanners

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/url"
	"strings"
	"sync"

	"github.com/izm1chael/mailhook/db"
	"github.com/izm1chael/mailhook/pipeline"
)

// feedManager is the interface the URL checker needs from feeds.Manager.
type feedManager interface {
	ContainsURL(rawURL string) bool
	LookupURL(rawURL string) (feed, threatType string, ok bool)
	// LookupURLExact is like LookupURL but skips the host-only fallback match.
	// Used for shared-hosting domains to avoid false positives.
	LookupURLExact(rawURL string) (feed, threatType string, ok bool)
}

// sharedHostingDomains is the set of large shared-hosting / CDN platforms where
// a host-level threat-feed match is almost always a false positive (a specific
// malicious path on the platform was indexed, not the platform itself).
// URLs on these domains are checked with exact-URL matching only.
var sharedHostingDomains = map[string]struct{}{
	"github.com":              {},
	"raw.githubusercontent.com": {},
	"gist.github.com":         {},
	"google.com":              {},
	"googleapis.com":          {},
	"googleusercontent.com":   {},
	"gstatic.com":             {},
	"drive.google.com":        {},
	"docs.google.com":         {},
	"microsoft.com":           {},
	"live.com":                {},
	"office.com":              {},
	"onedrive.live.com":       {},
	"sharepoint.com":          {},
	"apple.com":               {},
	"icloud.com":              {},
	"amazon.com":              {},
	"amazonaws.com":           {},
	"cloudfront.net":          {},
	"cloudflare.com":          {},
	"discord.com":             {},
	"discordapp.com":          {},
	"dropbox.com":             {},
	"pastebin.com":            {},
	"youtube.com":             {},
	"youtu.be":                {},
	"linkedin.com":            {},
	"twitter.com":             {},
	"x.com":                   {},
	"facebook.com":            {},
	"instagram.com":           {},
	"npm.js":                  {},
	"npmjs.com":               {},
	"pypi.org":                {},
	"stackoverflow.com":       {},
	"gitlab.com":              {},
	"bitbucket.org":           {},
}

// isSharedHostingDomain reports whether domain (already lowercased, www. stripped)
// is in the shared-hosting allowlist, checking both the exact host and its parent
// registered domain.
func isSharedHostingDomain(host string) bool {
	if _, ok := sharedHostingDomains[host]; ok {
		return true
	}
	// Check parent: strip one leading label (e.g. "raw.githubusercontent.com" → "githubusercontent.com")
	if dot := strings.IndexByte(host, '.'); dot >= 0 {
		if _, ok := sharedHostingDomains[host[dot+1:]]; ok {
			return true
		}
	}
	return false
}

// URLCheck looks up each extracted URL against the in-memory threat feed index.
type URLCheck struct {
	mu      sync.RWMutex
	enabled bool
	feeds   feedManager
	log     *slog.Logger
}

// NewURLCheck creates a URLCheck scanner backed by the given feed manager.
func NewURLCheck(feeds feedManager, log *slog.Logger) *URLCheck {
	return &URLCheck{enabled: true, feeds: feeds, log: log}
}

func (u *URLCheck) Name() string { return "urlcheck" }

// SetEnabled enables or disables the scanner at runtime.
func (u *URLCheck) SetEnabled(v bool) { u.mu.Lock(); u.enabled = v; u.mu.Unlock() }

// IsEnabled reports whether the scanner is currently enabled.
func (u *URLCheck) IsEnabled() bool { u.mu.RLock(); defer u.mu.RUnlock(); return u.enabled }

// Scan checks every URL in the email against the loaded threat feeds.
// Returns malicious if any URL matches; clean otherwise.
func (u *URLCheck) Scan(ctx context.Context, email *pipeline.Email) pipeline.ScanResult {
	u.mu.RLock()
	enabled := u.enabled
	u.mu.RUnlock()
	if !enabled {
		return pipeline.ScanResult{Scanner: u.Name(), Verdict: "skip", Detail: "disabled"}
	}

	if len(email.URLs) == 0 {
		return pipeline.ScanResult{Scanner: u.Name(), Verdict: "clean"}
	}
	if ctx.Err() != nil {
		return pipeline.ScanResult{Scanner: u.Name(), Verdict: "skip", Detail: "context cancelled"}
	}

	var hitDetails []db.URLHit
	for _, rawURL := range email.URLs {
		domain := extractURLDomain(rawURL)
		var feed, threatType string
		var ok bool
		if isSharedHostingDomain(domain) {
			// Shared hosting platforms: only flag if the exact URL matched, not
			// just the domain, to avoid false positives from path-specific entries.
			feed, threatType, ok = u.feeds.LookupURLExact(rawURL)
		} else {
			feed, threatType, ok = u.feeds.LookupURL(rawURL)
		}
		if ok {
			hitDetails = append(hitDetails, db.URLHit{
				URL:        rawURL,
				Domain:     domain,
				Feed:       feed,
				ThreatType: threatType,
			})
		}
	}

	if len(hitDetails) == 0 {
		return pipeline.ScanResult{Scanner: u.Name(), Verdict: "clean"}
	}

	var hitURLs []string
	for _, h := range hitDetails {
		hitURLs = append(hitURLs, h.URL)
	}
	detail := strings.Join(hitURLs, ", ")
	if len(detail) > 500 {
		detail = detail[:500] + "…"
	}
	matchData, _ := json.Marshal(hitDetails)

	return pipeline.ScanResult{
		Scanner: u.Name(),
		Verdict: "malicious",
		Detail:  detail,
		Matches: matchData,
	}
}

func extractURLDomain(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	host := strings.ToLower(u.Hostname())
	return strings.TrimPrefix(host, "www.")
}
