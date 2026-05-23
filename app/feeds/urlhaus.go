package feeds

import (
	"bufio"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const urlhausURL = "https://urlhaus.abuse.ch/downloads/csv_online/"

type urlhausFeed struct{}

func (urlhausFeed) Name() string { return "urlhaus" }

func (urlhausFeed) Fetch(ctx context.Context, cacheDir string) ([]string, error) {
	cachePath := filepath.Join(cacheDir, "urlhaus.csv")

	raw, err := httpGet(ctx, urlhausURL, "MailHook/1.0")
	if err != nil {
		// Fall back to cache
		return loadCacheFile(cachePath)
	}

	_ = writeFileSafe(cachePath, raw, 0o640) // cache miss is non-fatal; log on next failure

	return parseURLhaus(raw)
}

func parseURLhaus(raw []byte) ([]string, error) {
	r := csv.NewReader(strings.NewReader(string(raw)))
	r.Comment = '#'
	r.FieldsPerRecord = -1 // variable columns

	var urls []string
	for {
		record, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}
		// CSV columns: id, dateadded, url, url_status, last_online, threat, tags, urlhaus_link, reporter
		if len(record) < 4 {
			continue
		}
		rawURL := strings.TrimSpace(record[2])
		status := strings.TrimSpace(record[3])
		if status != "online" || rawURL == "" {
			continue
		}
		urls = append(urls, rawURL)
	}
	return urls, nil
}

// openphishFeed fetches the OpenPhish community feed — one URL per line.
type openphishFeed struct{}

func (openphishFeed) Name() string { return "openphish" }

func (openphishFeed) Fetch(ctx context.Context, cacheDir string) ([]string, error) {
	const feedURL = "https://openphish.com/feed.txt"
	cachePath := filepath.Join(cacheDir, "openphish.txt")

	raw, err := httpGet(ctx, feedURL, "MailHook/1.0")
	if err != nil {
		return loadCacheFile(cachePath)
	}
	_ = writeFileSafe(cachePath, raw, 0o640) // cache miss is non-fatal
	return parseLineFile(raw), nil
}

func parseLineFile(raw []byte) []string {
	var urls []string
	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" && strings.HasPrefix(line, "http") {
			urls = append(urls, line)
		}
	}
	return urls
}

// phishtankFeed fetches the PhishTank online-valid JSON feed.
type phishtankFeed struct{}

func (phishtankFeed) Name() string { return "phishtank" }

func (phishtankFeed) Fetch(ctx context.Context, cacheDir string) ([]string, error) {
	const feedURL = "https://data.phishtank.com/data/online-valid.json"
	cachePath := filepath.Join(cacheDir, "phishtank.json")

	// PhishTank requires this user-agent or returns 403
	fetchCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(fetchCtx, http.MethodGet, feedURL, nil)
	if err != nil {
		return loadCacheFile(cachePath)
	}
	req.Header.Set("User-Agent", "phishtank/mailhook")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return loadCacheFile(cachePath)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return loadCacheFile(cachePath)
	}
	defer resp.Body.Close()

	// Tee into cache while streaming the JSON decode — avoids buffering the full feed in RAM (F-045).
	cacheF, cacheErr := os.CreateTemp(filepath.Dir(cachePath), ".phishtank-cache-*")
	var reader io.Reader
	if cacheErr == nil {
		reader = io.TeeReader(io.LimitReader(resp.Body, 256*1024*1024), cacheF)
	} else {
		reader = io.LimitReader(resp.Body, 256*1024*1024)
	}

	urls, parseErr := parsePhishTankJSONStream(reader)
	if cacheErr == nil {
		tmpName := cacheF.Name()
		cacheF.Close()
		if parseErr == nil {
			_ = os.Rename(tmpName, cachePath)
		} else {
			os.Remove(tmpName) //nolint:errcheck
		}
	}
	if parseErr != nil {
		return loadCacheFile(cachePath)
	}
	return urls, nil
}

func parsePhishTankJSON(raw []byte) ([]string, error) {
	return parsePhishTankJSONStream(bytes.NewReader(raw))
}

func parsePhishTankJSONStream(r io.Reader) ([]string, error) {
	// PhishTank JSON is an array of objects: [{"url":"...","verified":true,...},...]
	// Use json.Decoder streaming to avoid loading the entire feed into memory.
	type entry struct {
		URL      string `json:"url"`
		Verified bool   `json:"verified"`
	}

	dec := json.NewDecoder(r)
	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("phishtank: read opening token: %w", err)
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '[' {
		return nil, fmt.Errorf("phishtank: expected JSON array, got %v", tok)
	}

	var urls []string
	for dec.More() {
		var e entry
		if err := dec.Decode(&e); err != nil {
			return nil, fmt.Errorf("phishtank: decode entry: %w", err)
		}
		if e.Verified && e.URL != "" {
			urls = append(urls, e.URL)
		}
	}
	return urls, nil
}

// httpGet performs a GET request with the given user-agent and a 30s timeout.
func httpGet(ctx context.Context, rawURL, userAgent string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, rawURL)
	}

	return io.ReadAll(io.LimitReader(resp.Body, 256*1024*1024)) // 256MB max
}

func loadCacheFile(path string) ([]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("no cache at %s: %w", path, err)
	}
	ext := filepath.Ext(path)
	switch ext {
	case ".csv":
		return parseURLhaus(raw)
	case ".txt":
		return parseLineFile(raw), nil
	case ".json":
		return parsePhishTankJSON(raw)
	}
	return parseLineFile(raw), nil
}

// normalizeURL returns a lookup key for a URL: lowercase scheme+host+path, no www. prefix.
func normalizeURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return strings.ToLower(rawURL)
	}
	host := strings.ToLower(u.Hostname())
	host = strings.TrimPrefix(host, "www.")
	return host + u.Path
}
