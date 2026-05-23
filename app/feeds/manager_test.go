package feeds

import (
	"context"
	"log/slog"
	"os"
	"testing"
)

// stubFeed is a test double for the feed interface.
type stubFeed struct {
	name  string
	urls  []string
	fails bool
}

func (s *stubFeed) Name() string { return s.name }
func (s *stubFeed) Fetch(_ context.Context, _ string) ([]string, error) {
	if s.fails {
		return nil, os.ErrDeadlineExceeded
	}
	return s.urls, nil
}

func newTestManager(feeds []feed) *Manager {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	m := &Manager{
		index:    make(map[string]struct{}),
		feedURLs: make(map[string]map[string]struct{}),
		feedCounts: make(map[string]int),
		cacheDir: t_tempDir(),
		feeds:    feeds,
		log:      log,
	}
	return m
}

// t_tempDir is a package-level temp dir helper (os.MkdirTemp without *testing.T).
func t_tempDir() string {
	d, _ := os.MkdirTemp("", "feeds-test-*")
	return d
}

func TestRefresh_AllFeedsSucceed(t *testing.T) {
	m := newTestManager([]feed{
		&stubFeed{name: "feed_a", urls: []string{"http://evil.com/bad", "http://phish.org/hook"}},
		&stubFeed{name: "feed_b", urls: []string{"http://malware.net/payload"}},
	})
	defer os.RemoveAll(m.cacheDir)

	m.Refresh(context.Background())

	if !m.ContainsURL("http://evil.com/bad") {
		t.Error("expected ContainsURL=true for feed_a URL")
	}
	if !m.ContainsURL("http://malware.net/payload") {
		t.Error("expected ContainsURL=true for feed_b URL")
	}
}

// TestRefresh_FeedAmnesiaPrevention verifies that when a feed fetch fails on the
// second refresh, entries from that feed are retained from the first successful load.
func TestRefresh_FeedAmnesiaPrevention(t *testing.T) {
	feedA := &stubFeed{name: "feed_a", urls: []string{"http://evil.com/bad"}}
	feedB := &stubFeed{name: "feed_b", urls: []string{"http://good-threat.com/x"}}

	m := newTestManager([]feed{feedA, feedB})
	defer os.RemoveAll(m.cacheDir)

	// First refresh — both feeds succeed.
	m.Refresh(context.Background())
	if !m.ContainsURL("http://evil.com/bad") {
		t.Fatal("first refresh: feed_a URL should be present")
	}
	if !m.ContainsURL("http://good-threat.com/x") {
		t.Fatal("first refresh: feed_b URL should be present")
	}

	// Second refresh — feed_a fails; feed_b succeeds.
	feedA.fails = true
	m.Refresh(context.Background())

	// feed_a entries must be retained (amnesia prevention).
	if !m.ContainsURL("http://evil.com/bad") {
		t.Error("second refresh: feed_a URL should be retained after fetch failure")
	}
	// feed_b entries should still be present.
	if !m.ContainsURL("http://good-threat.com/x") {
		t.Error("second refresh: feed_b URL should still be present")
	}
}

// TestRefresh_ExpiredEntriesDroppedWhenFeedRecovers verifies that stale entries
// from a feed are replaced when it successfully returns new data.
func TestRefresh_ExpiredEntriesDroppedWhenFeedRecovers(t *testing.T) {
	feedA := &stubFeed{name: "feed_a", urls: []string{"http://old-threat.com/x"}}

	m := newTestManager([]feed{feedA})
	defer os.RemoveAll(m.cacheDir)

	// First refresh populates old URL.
	m.Refresh(context.Background())
	if !m.ContainsURL("http://old-threat.com/x") {
		t.Fatal("setup: old URL should be present")
	}

	// Second refresh — feed returns new URLs, old one removed.
	feedA.urls = []string{"http://new-threat.com/y"}
	m.Refresh(context.Background())

	if m.ContainsURL("http://old-threat.com/x") {
		t.Error("old URL should be removed when feed returns new data")
	}
	if !m.ContainsURL("http://new-threat.com/y") {
		t.Error("new URL should be present after successful refresh")
	}
}

func TestContainsURL_HostMatchWithoutPath(t *testing.T) {
	m := newTestManager([]feed{
		&stubFeed{name: "f", urls: []string{"http://evil.com/path/to/payload"}},
	})
	defer os.RemoveAll(m.cacheDir)

	m.Refresh(context.Background())

	// Host-only match should work (the manager also indexes the bare hostname).
	if !m.ContainsURL("http://evil.com/other") {
		t.Error("expected host-level match for evil.com")
	}
}

func TestLookupURL_ReturnsFeedAndThreatType(t *testing.T) {
	m := newTestManager([]feed{
		&stubFeed{name: "urlhaus", urls: []string{"http://malware.example/payload"}},
		&stubFeed{name: "phishtank", urls: []string{"http://phish.example/login"}},
		&stubFeed{name: "openphish", urls: []string{"http://openphish.example/hook"}},
	})
	defer os.RemoveAll(m.cacheDir)
	m.Refresh(context.Background())

	cases := []struct {
		url        string
		wantFeed   string
		wantThreat string
		wantOK     bool
	}{
		{"http://malware.example/payload", "urlhaus", "malware", true},
		{"http://phish.example/login", "phishtank", "phishing", true},
		{"http://openphish.example/hook", "openphish", "phishing", true},
		{"http://clean.example/", "", "", false},
	}

	for _, tc := range cases {
		feed, threatType, ok := m.LookupURL(tc.url)
		if ok != tc.wantOK {
			t.Errorf("LookupURL(%q) ok=%v, want %v", tc.url, ok, tc.wantOK)
		}
		if ok && feed != tc.wantFeed {
			t.Errorf("LookupURL(%q) feed=%q, want %q", tc.url, feed, tc.wantFeed)
		}
		if ok && threatType != tc.wantThreat {
			t.Errorf("LookupURL(%q) threatType=%q, want %q", tc.url, threatType, tc.wantThreat)
		}
	}
}

func TestLookupURL_HostOnlyMatch(t *testing.T) {
	// URLhaus and ThreatFox do NOT host-index to avoid false positives on
	// compromised-but-not-fully-malicious domains. Only an exact URL match
	// should return ok=true for these feeds.
	m := newTestManager([]feed{
		&stubFeed{name: "urlhaus", urls: []string{"http://evil.example/specific/path"}},
	})
	defer os.RemoveAll(m.cacheDir)
	m.Refresh(context.Background())

	// Exact URL matches.
	_, _, ok := m.LookupURL("http://evil.example/specific/path")
	if !ok {
		t.Fatal("expected LookupURL to return ok=true for exact URL match")
	}

	// A different path on the same host must NOT match (no host-index for urlhaus).
	_, _, ok = m.LookupURL("http://evil.example/different/path")
	if ok {
		t.Fatal("expected LookupURL to return ok=false for urlhaus host-only match (host-indexing disabled)")
	}
}
