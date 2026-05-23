package feeds

import (
	"context"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/izm1chael/mailhook/db"
	"gorm.io/gorm"
)

// feed is the interface each individual feed source implements.
type feed interface {
	Name() string
	Fetch(ctx context.Context, cacheDir string) ([]string, error)
}

// Manager holds the in-memory URL/domain index and refreshes it periodically.
type Manager struct {
	mu         sync.RWMutex
	index      map[string]struct{}            // normalized host+path → present
	feedURLs   map[string]map[string]struct{} // per-feed URL sets for amnesia protection
	feedCounts map[string]int                 // per-feed entry counts for health/metrics
	lastLoaded time.Time
	cacheDir   string
	feeds      []feed
	hashFeeds  []hashFeed
	gdb        *db.DB
	log        *slog.Logger
}

// New creates a Manager that loads URLhaus, OpenPhish, and PhishTank feeds.
func New(cacheDir string, gdb *db.DB, log *slog.Logger) *Manager {
	m := &Manager{
		index:      make(map[string]struct{}),
		feedURLs:   make(map[string]map[string]struct{}),
		feedCounts: make(map[string]int),
		cacheDir:   cacheDir,
		gdb:        gdb,
		log:        log,
	}
	m.feeds = []feed{
		urlhausFeed{},
		openphishFeed{},
		phishtankFeed{},
		threatfoxFeed{},
	}
	m.hashFeeds = []hashFeed{
		malwareBazaarFeed{},
	}
	return m
}

// Refresh fetches all feeds and atomically rebuilds the in-memory index.
// If a feed fetch fails, the previous URLs for that feed are retained so the
// index never silently loses entries due to a transient outage ("feed amnesia").
func (m *Manager) Refresh(ctx context.Context) {
	newIndex := make(map[string]struct{})
	newFeedURLs := make(map[string]map[string]struct{})
	counts := make(map[string]int)

	// Snapshot previous feed URL sets under read lock so we can fall back to them
	// if a fetch fails this round.
	m.mu.RLock()
	prevFeedURLs := m.feedURLs
	m.mu.RUnlock()

	for _, f := range m.feeds {
		urls, err := f.Fetch(ctx, m.cacheDir)
		if err != nil {
			m.log.Warn("feed fetch failed, retaining previous entries", "feed", f.Name(), "err", err)
			// Retain the previous URL set for this feed to prevent index amnesia.
			if prev, ok := prevFeedURLs[f.Name()]; ok {
				for u := range prev {
					newIndex[u] = struct{}{}
				}
				newFeedURLs[f.Name()] = prev
			}
			continue
		}

		// URLhaus and ThreatFox list specific malicious paths on often-compromised
		// legitimate sites. Host-level indexing for these feeds causes false positives
		// (any URL on a once-compromised domain flags as malicious). Only index the
		// exact URL for these feeds; phishing feeds (OpenPhish, PhishTank) use
		// dedicated phishing domains so host matching is appropriate there.
		hostIndex := f.Name() != "urlhaus" && f.Name() != "threatfox"

		thisFeedURLs := make(map[string]struct{}, len(urls)*2)
		for _, rawURL := range urls {
			key := normalizeURL(rawURL)
			if key != "" {
				newIndex[key] = struct{}{}
				thisFeedURLs[key] = struct{}{}
				if hostIndex {
					// Also index the host alone so a domain match works without a path
					if u, err2 := url.Parse(rawURL); err2 == nil {
						host := strings.ToLower(strings.TrimPrefix(u.Hostname(), "www."))
						if host != "" {
							newIndex[host] = struct{}{}
							thisFeedURLs[host] = struct{}{}
						}
					}
				}
			}
		}
		newFeedURLs[f.Name()] = thisFeedURLs
		counts[f.Name()] = len(urls)

		// Persist metadata
		if m.gdb != nil {
			if err := m.gdb.Write(func(tx *gorm.DB) error {
				return tx.Save(&db.FeedMeta{
					Name:          f.Name(),
					LastRefreshed: time.Now(),
					EntryCount:    len(urls),
					LoadedAt:      time.Now(),
				}).Error
			}); err != nil {
				m.log.Warn("feeds: failed to persist feed metadata", "feed", f.Name(), "err", err)
			}
		}
	}

	m.mu.Lock()
	m.index = newIndex
	m.feedURLs = newFeedURLs
	m.feedCounts = counts
	m.lastLoaded = time.Now()
	m.mu.Unlock()

	m.log.Info("feeds loaded",
		"total_entries", len(newIndex),
		"urlhaus", counts["urlhaus"],
		"openphish", counts["openphish"],
		"phishtank", counts["phishtank"],
		"threatfox", counts["threatfox"],
	)

	// Sync hash-based feeds (write to SQLite, not the in-memory index).
	for _, hf := range m.hashFeeds {
		n, err := hf.Sync(ctx, m.cacheDir, m.gdb, m.log)
		if err != nil {
			m.log.Warn("hash feed sync failed", "feed", hf.Name(), "err", err)
			continue
		}
		m.log.Info("hash feed synced", "feed", hf.Name(), "rows", n)
		if m.gdb != nil {
			if err := m.gdb.Write(func(tx *gorm.DB) error {
				return tx.Save(&db.FeedMeta{
					Name:          hf.Name(),
					LastRefreshed: time.Now(),
					EntryCount:    n,
					LoadedAt:      time.Now(),
				}).Error
			}); err != nil {
				m.log.Warn("feeds: failed to persist hash feed metadata", "feed", hf.Name(), "err", err)
			}
		}
	}
}

// Run starts the background refresh scheduler. Blocks until ctx is cancelled.
func (m *Manager) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			m.Refresh(ctx)
		case <-ctx.Done():
			return
		}
	}
}

// ContainsURL reports whether rawURL (or its host) appears in any loaded feed or custom DB entries.
func (m *Manager) ContainsURL(rawURL string) bool {
	m.mu.RLock()
	key := normalizeURL(rawURL)
	_, inIndex := m.index[key]
	var hostInIndex bool
	var host string
	if u, err := url.Parse(rawURL); err == nil {
		host = strings.ToLower(strings.TrimPrefix(u.Hostname(), "www."))
		_, hostInIndex = m.index[host]
	}
	m.mu.RUnlock()

	if inIndex || hostInIndex {
		return true
	}

	if m.gdb != nil && host != "" {
		var count int64
		m.gdb.Model(&db.CustomFeedEntry{}).
			Where("(entry_type = 'domain' AND (? = entry OR ? LIKE '%.' || entry)) OR (entry_type = 'url' AND entry = ?)", host, host, rawURL).
			Count(&count)
		if count > 0 {
			return true
		}
	}
	return false
}

// LookupURLExact returns the first feed that contains an exact (full-URL) match for
// rawURL. Unlike LookupURL it does NOT fall back to host-only matching, so it will
// not fire on a shared hosting domain (e.g. github.com) just because a specific path
// on that host appeared in a feed. Use this for URLs whose domain is a known CDN or
// large hosting platform where a domain-level match would be a false positive.
func (m *Manager) LookupURLExact(rawURL string) (feed, threatType string, ok bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	key := normalizeURL(rawURL)
	feedTypes := map[string]string{
		"urlhaus":   "malware",
		"phishtank": "phishing",
		"openphish": "phishing",
		"threatfox": "malware",
	}
	for feedName, urls := range m.feedURLs {
		if _, matched := urls[key]; matched {
			return feedName, feedTypes[feedName], true
		}
	}
	return "", "", false
}

// LookupURL returns the first feed that contains rawURL (or its host), along with its
// threat type ("malware" or "phishing"). Returns ok=false if not found in any feed.
func (m *Manager) LookupURL(rawURL string) (feed, threatType string, ok bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	key := normalizeURL(rawURL)
	var host string
	if u, err := url.Parse(rawURL); err == nil {
		host = strings.ToLower(strings.TrimPrefix(u.Hostname(), "www."))
	}

	feedTypes := map[string]string{
		"urlhaus":   "malware",
		"phishtank": "phishing",
		"openphish": "phishing",
		"threatfox": "malware",
	}
	for feedName, urls := range m.feedURLs {
		if _, matched := urls[key]; matched {
			return feedName, feedTypes[feedName], true
		}
		if host != "" {
			if _, matched := urls[host]; matched {
				return feedName, feedTypes[feedName], true
			}
		}
	}
	return "", "", false
}

// LookupHash checks whether sha256 appears in the MalwareBazaarHash table.
// Returns (true, signature) if found, (false, "") otherwise.
func (m *Manager) LookupHash(sha256 string) (found bool, signature string) {
	if m.gdb == nil {
		return false, ""
	}
	var row db.MalwareBazaarHash
	if err := m.gdb.Where("sha256 = ?", sha256).First(&row).Error; err != nil {
		return false, ""
	}
	return true, row.Signature
}

// EntryCount returns the total number of entries in the index.
func (m *Manager) EntryCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.index)
}

// writeFileSafe atomically writes data to path by writing to a temp file and
// renaming, so a crash mid-write never leaves a truncated cache file on disk.
func writeFileSafe(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// FeedStats returns per-feed entry counts and the time feeds were last loaded.
func (m *Manager) FeedStats() (counts map[string]int, lastLoaded time.Time) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[string]int, len(m.feedCounts))
	for k, v := range m.feedCounts {
		out[k] = v
	}
	return out, m.lastLoaded
}
