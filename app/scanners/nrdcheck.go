package scanners

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/izm1chael/mailhook/config"
	"github.com/izm1chael/mailhook/db"
	"github.com/izm1chael/mailhook/pipeline"
	"github.com/izm1chael/mailhook/util"
	"gorm.io/gorm"
)

// ldhDomain matches valid LDH (letters, digits, hyphens) hostnames per RFC 952/1123.
// Rejects paths, query strings, or any character that would allow URL injection.
var ldhDomain = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`)

func isValidDomain(d string) bool {
	return len(d) > 0 && len(d) <= 253 && ldhDomain.MatchString(d)
}


// rdapResponse is the subset of the RDAP domain object we need.
// RDAP is defined in RFC 7483; the events array always uses this structure.
type rdapResponse struct {
	Events []struct {
		EventAction string `json:"eventAction"`
		EventDate   string `json:"eventDate"`
	} `json:"events"`
}

// NRDCheck queries RDAP to detect newly registered domains in the sender address
// and in URLs found in the email body. Results are cached in SQLite.
type NRDCheck struct {
	mu           sync.RWMutex
	enabled      bool
	gdb          *db.DB
	maxAgeDays   int
	cacheTTL     time.Duration
	failCacheTTL time.Duration // TTL for negative / 404 cache entries
	rdapBaseURL  string
	client       *http.Client
	log          *slog.Logger
}

// NewNRDCheck creates an NRDCheck scanner.
func NewNRDCheck(gdb *db.DB, cfg *config.Config, log *slog.Logger) *NRDCheck {
	httpsOK := strings.HasPrefix(cfg.NRDRDAPBaseURL, "https://")
	if cfg.NRDEnabled && !httpsOK {
		log.Warn("nrdcheck: MAILHOOK_NRD_RDAP_BASE_URL must start with https://; NRD checks will be disabled",
			"rdap_base_url", cfg.NRDRDAPBaseURL)
	}
	return &NRDCheck{
		enabled:      cfg.NRDEnabled && httpsOK,
		gdb:          gdb,
		maxAgeDays:   cfg.NRDMaxAgeDays,
		cacheTTL:     time.Duration(cfg.NRDCacheTTLHours) * time.Hour,
		failCacheTTL: time.Hour,
		rdapBaseURL:  cfg.NRDRDAPBaseURL,
		client:       newSSRFSafeClient(),
		log:          log,
	}
}

// newSSRFSafeClient returns an HTTP client that refuses to connect to private/loopback
// addresses. This prevents SSRF via redirect chains or a misconfigured rdapBaseURL.
func newSSRFSafeClient() *http.Client {
	dialer := &net.Dialer{}
	return &http.Client{
		Timeout: 10 * time.Second,
		// Never follow redirects — the RDAP spec does not require them and following
		// a redirect could land on a private address.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			DisableKeepAlives: true,
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
			// Satisfy the interface — actual control happens in DialContext above.
			DialTLSContext: nil,
		},
	}
}


func (n *NRDCheck) Name() string { return "nrdcheck" }

// SetHTTPClient replaces the scanner's HTTP client. Used in tests to inject a
// client that allows loopback connections (bypassing the SSRF guard).
func (n *NRDCheck) SetHTTPClient(c *http.Client) { n.client = c }

// SetEnabled enables or disables the scanner at runtime.
func (n *NRDCheck) SetEnabled(v bool) { n.mu.Lock(); n.enabled = v; n.mu.Unlock() }

// IsEnabled reports whether the scanner is currently enabled.
func (n *NRDCheck) IsEnabled() bool { n.mu.RLock(); defer n.mu.RUnlock(); return n.enabled }

// Scan checks the From: domain and all URL domains for recent registration.
// Returns suspicious (score 0.6) if any domain was registered within NRDMaxAgeDays.
func (n *NRDCheck) Scan(ctx context.Context, email *pipeline.Email) pipeline.ScanResult {
	n.mu.RLock()
	enabled := n.enabled
	n.mu.RUnlock()
	if !enabled {
		return pipeline.ScanResult{Scanner: n.Name(), Verdict: "skip", Detail: "disabled"}
	}

	// Collect unique domains with their source annotation.
	type domainSource struct {
		domain string
		source string // "from" | "url"
	}
	seen := make(map[string]struct{})
	var domains []domainSource

	addDomain := func(d, src string) {
		if d == "" {
			return
		}
		d = strings.ToLower(d)
		if _, ok := seen[d]; ok {
			return
		}
		seen[d] = struct{}{}
		domains = append(domains, domainSource{d, src})
	}

	addDomain(extractEmailDomain(email.From), "from")
	for _, rawURL := range email.URLs {
		addDomain(extractURLDomain(rawURL), "url")
	}

	if len(domains) == 0 {
		return pipeline.ScanResult{Scanner: n.Name(), Verdict: "clean"}
	}

	var hits []db.NRDHit
	for _, ds := range domains {
		regDate, found, err := n.checkDomain(ctx, ds.domain)
		if err != nil {
			n.log.Debug("nrdcheck: domain lookup error", "domain", ds.domain, "err", err)
			continue
		}
		if !found {
			continue
		}
		ageDays := int(time.Since(regDate).Hours() / 24)
		if ageDays <= n.maxAgeDays {
			hits = append(hits, db.NRDHit{
				Domain:           ds.domain,
				RegistrationDate: regDate.UTC().Format(time.RFC3339),
				AgeDays:          ageDays,
				Source:           ds.source,
			})
		}
	}

	if len(hits) == 0 {
		return pipeline.ScanResult{Scanner: n.Name(), Verdict: "clean"}
	}

	matchData, _ := json.Marshal(hits)
	var domainNames []string
	for _, h := range hits {
		domainNames = append(domainNames, fmt.Sprintf("%s (%dd old)", h.Domain, h.AgeDays))
	}
	detail := strings.Join(domainNames, ", ")
	if len(detail) > 500 {
		detail = detail[:500] + "…"
	}

	return pipeline.ScanResult{
		Scanner: n.Name(),
		Verdict: "suspicious",
		Score:   0.6,
		Detail:  detail,
		Matches: matchData,
	}
}

// checkDomain returns the registration date for domain, using the SQLite cache
// to avoid redundant RDAP queries.
func (n *NRDCheck) checkDomain(ctx context.Context, domain string) (regDate time.Time, found bool, err error) {
	// Check cache first.
	var cached db.NRDCache
	cacheErr := n.gdb.Where("domain = ? AND expires_at > ?", domain, time.Now()).First(&cached).Error
	if cacheErr == nil {
		if !cached.LookupSuccess {
			return time.Time{}, false, nil
		}
		return cached.RegistrationDate, !cached.RegistrationDate.IsZero(), nil
	}

	// Cache miss — query RDAP.
	regDate, found, err = n.rdapLookup(ctx, domain)
	if err != nil {
		// Transient errors are not cached so the next email can retry.
		return time.Time{}, false, err
	}

	// Write cache entry.
	ttl := n.cacheTTL
	if !found {
		ttl = n.failCacheTTL
	}
	now := time.Now()
	entry := db.NRDCache{
		Domain:           domain,
		RegistrationDate: regDate,
		LookupSuccess:    found,
		FetchedAt:        now,
		ExpiresAt:        now.Add(ttl),
	}
	if writeErr := n.gdb.Write(func(tx *gorm.DB) error {
		return tx.Save(&entry).Error
	}); writeErr != nil {
		n.log.Warn("nrdcheck: failed to cache result", "domain", domain, "err", writeErr)
	}

	return regDate, found, nil
}

// rdapLookup queries the RDAP bootstrap service for the domain's registration date.
// Returns found=false (no error) for unknown domains (HTTP 404).
// Returns an error for transient failures (network errors, HTTP 5xx) so callers can retry.
func (n *NRDCheck) rdapLookup(ctx context.Context, domain string) (regDate time.Time, found bool, err error) {
	if !isValidDomain(domain) {
		return time.Time{}, false, fmt.Errorf("nrdcheck: invalid domain %q", domain)
	}
	rdapURL := n.rdapBaseURL + domain
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rdapURL, http.NoBody)
	if err != nil {
		return time.Time{}, false, err
	}
	req.Header.Set("Accept", "application/rdap+json, application/json")
	req.Header.Set("User-Agent", "MailHook-NRDCheck/1.0")

	resp, err := n.client.Do(req)
	if err != nil {
		return time.Time{}, false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		// Domain not found in RDAP registry — treat as unknown, not an error.
		return time.Time{}, false, nil
	}
	if resp.StatusCode >= 500 {
		return time.Time{}, false, fmt.Errorf("RDAP server error: HTTP %d for %s", resp.StatusCode, domain)
	}
	if resp.StatusCode != http.StatusOK {
		// Other unexpected status — not an error we can act on.
		return time.Time{}, false, nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return time.Time{}, false, err
	}

	var rdap rdapResponse
	if err := json.Unmarshal(body, &rdap); err != nil {
		n.log.Warn("nrdcheck: malformed RDAP JSON", "domain", domain, "err", err)
		return time.Time{}, false, nil
	}

	for _, event := range rdap.Events {
		if strings.EqualFold(event.EventAction, "registration") {
			regDate = parseRDAPDate(event.EventDate)
			if !regDate.IsZero() {
				return regDate, true, nil
			}
		}
	}

	// RDAP response present but no registration event found.
	return time.Time{}, false, nil
}

// parseRDAPDate parses an RDAP eventDate string.
// Tries RFC3339 first, then date-only format as a fallback (some registries omit the time).
func parseRDAPDate(s string) time.Time {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t
	}
	return time.Time{}
}

// extractEmailDomain returns the domain part of an email address.
// Returns "" if the domain fails LDH validation (prevents path injection in RDAP URLs).
func extractEmailDomain(addr string) string {
	// Strip display name and angle brackets: "Display <user@domain>" → "user@domain"
	addr = strings.TrimSpace(addr)
	if i := strings.LastIndex(addr, "<"); i >= 0 {
		addr = strings.TrimSuffix(strings.TrimSpace(addr[i+1:]), ">")
	}
	if i := strings.LastIndex(addr, "@"); i >= 0 {
		domain := strings.ToLower(addr[i+1:])
		if !isValidDomain(domain) {
			return ""
		}
		return domain
	}
	return ""
}
