package scanners

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
	"gorm.io/gorm"

	"github.com/izm1chael/mailhook/db"
	"github.com/izm1chael/mailhook/pipeline"
	"github.com/izm1chael/mailhook/util"
)

// VirusTotal performs hash lookups against the VirusTotal v3 API.
// Only executable attachments are checked to minimize API usage.
type VirusTotal struct {
	mu               sync.RWMutex
	apiKey           string
	enabled          bool
	gdb              *db.DB
	limiter          *rate.Limiter // free tier: 4 requests/min
	client           *http.Client
	log              *slog.Logger
	cacheTTL         time.Duration // TTL for positive results
	notFoundCacheTTL time.Duration // shorter TTL for 0/0 not-found results
	vtBaseURL        string        // overrideable in tests; defaults to VT API v3 root
}

type vtFileResponse struct {
	Data struct {
		Attributes struct {
			LastAnalysisStats struct {
				Malicious  int `json:"malicious"`
				Suspicious int `json:"suspicious"`
				Undetected int `json:"undetected"`
				Harmless   int `json:"harmless"`
			} `json:"last_analysis_stats"`
		} `json:"attributes"`
	} `json:"data"`
}

// NewVirusTotal creates a VirusTotal scanner. If apiKey is empty the scanner
// returns "skip" on every call without making any network requests.
// cacheTTL controls how long positive results are cached; notFoundTTL controls
// the shorter TTL for 0/0 results (a sample may become known-malicious later).
func NewVirusTotal(apiKey string, gdb *db.DB, log *slog.Logger, cacheTTL, notFoundTTL time.Duration) *VirusTotal {
	return &VirusTotal{
		apiKey:           apiKey,
		enabled:          true,
		gdb:              gdb,
		limiter:          rate.NewLimiter(rate.Every(15*time.Second), 1), // 4/min = 1 per 15s
		client:           &http.Client{Timeout: 15 * time.Second},
		log:              log,
		cacheTTL:         cacheTTL,
		notFoundCacheTTL: notFoundTTL,
	}
}

// SetEnabled enables or disables the scanner at runtime.
func (v *VirusTotal) SetEnabled(b bool) { v.mu.Lock(); v.enabled = b; v.mu.Unlock() }

// IsEnabled reports whether the scanner is currently enabled.
func (v *VirusTotal) IsEnabled() bool { v.mu.RLock(); defer v.mu.RUnlock(); return v.enabled }

func (v *VirusTotal) Name() string { return "virustotal" }

// SetAPIKey updates the API key at runtime without restarting.
func (v *VirusTotal) SetAPIKey(key string) {
	v.mu.Lock()
	v.apiKey = key
	v.mu.Unlock()
}

// SetVTBaseURL overrides the VirusTotal API base URL. Used in tests to redirect
// requests to a mock HTTP server. Must be called before any scans are started.
func (v *VirusTotal) SetVTBaseURL(baseURL string) {
	v.mu.Lock()
	v.vtBaseURL = baseURL
	v.mu.Unlock()
}

// Scan checks the SHA256 of each dangerous attachment against VirusTotal.
// Uses a non-blocking TryAcquire so the pipeline is never stalled waiting for
// a rate-limit token — if the limiter is exhausted the scanner returns "skip".
func (v *VirusTotal) Scan(ctx context.Context, email *pipeline.Email) pipeline.ScanResult {
	v.mu.RLock()
	apiKey := v.apiKey
	enabled := v.enabled
	v.mu.RUnlock()
	if !enabled {
		return pipeline.ScanResult{Scanner: v.Name(), Verdict: "skip", Detail: "disabled"}
	}
	if apiKey == "" || len(email.Attachments) == 0 {
		return pipeline.ScanResult{Scanner: v.Name(), Verdict: "skip"}
	}

	var totalPositives int
	var vtResults []db.VTResult
	for _, att := range email.Attachments {
		if !att.IsDangerous {
			continue
		}

		// Non-blocking rate limit check — never stall the pipeline
		if !v.limiter.Allow() {
			v.log.Debug("virustotal rate limit queue full, skipping", "sha256", att.SHA256)
			return pipeline.ScanResult{Scanner: v.Name(), Verdict: "skip", Detail: "VT rate limit queue full"}
		}

		positives, total, source, err := v.lookupHash(ctx, att.SHA256, apiKey)
		if err != nil {
			v.log.Warn("virustotal lookup failed", "sha256", att.SHA256, "err", err)
			continue
		}
		v.log.Debug("virustotal result", "sha256", util.SHA256Hex([]byte(att.SHA256)), "positives", positives, "source", source)
		totalPositives += positives
		vtResults = append(vtResults, db.VTResult{
			SHA256:    att.SHA256,
			Filename:  att.Filename,
			Positives: positives,
			Total:     total,
			Source:    source,
		})
	}

	matchData, _ := json.Marshal(vtResults)

	if totalPositives == 0 {
		return pipeline.ScanResult{Scanner: v.Name(), Verdict: "clean", Score: 0, Matches: matchData}
	}

	verdict := "suspicious"
	if totalPositives >= 3 {
		verdict = "malicious"
	}
	return pipeline.ScanResult{
		Scanner: v.Name(),
		Verdict: verdict,
		Score:   float64(totalPositives),
		Detail:  fmt.Sprintf("VirusTotal: %d engine(s) flagged attachment", totalPositives),
		Matches: matchData,
	}
}

func (v *VirusTotal) lookupHash(ctx context.Context, sha256 string, apiKey string) (positives, total int, source string, err error) {
	// Check cache with TTL. Not-found (0/0) results use a shorter TTL since a
	// sample may become known-malicious after the initial lookup.
	var cached db.VTHashCache
	if err := v.gdb.Where("sha256 = ?", sha256).First(&cached).Error; err == nil {
		ttl := v.cacheTTL
		if cached.Positives == 0 && cached.Total == 0 {
			ttl = v.notFoundCacheTTL
		}
		if time.Since(cached.FetchedAt) < ttl {
			return cached.Positives, cached.Total, "cache", nil
		}
		// Cache expired — fall through to API and upsert a fresh row
	}

	// API call
	v.mu.RLock()
	baseURL := v.vtBaseURL
	v.mu.RUnlock()
	if baseURL == "" {
		baseURL = "https://www.virustotal.com/api/v3"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		fmt.Sprintf("%s/files/%s", baseURL, sha256), nil)
	if err != nil {
		return 0, 0, "", err
	}
	req.Header.Set("x-apikey", apiKey)

	resp, err := v.client.Do(req)
	if err != nil {
		return 0, 0, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		if err := v.gdb.Write(func(tx *gorm.DB) error {
			return tx.Save(&db.VTHashCache{SHA256: sha256, Positives: 0, Total: 0, FetchedAt: time.Now()}).Error
		}); err != nil {
			v.log.Warn("virustotal: failed to cache not-found result", "sha256", sha256, "err", err)
		}
		return 0, 0, "api", nil
	}

	if resp.StatusCode != http.StatusOK {
		return 0, 0, "", fmt.Errorf("virustotal returned HTTP %d", resp.StatusCode)
	}

	var vtResp vtFileResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64*1024)).Decode(&vtResp); err != nil {
		return 0, 0, "", fmt.Errorf("decode: %w", err)
	}

	stats := vtResp.Data.Attributes.LastAnalysisStats
	t := stats.Malicious + stats.Suspicious + stats.Undetected + stats.Harmless

	if err := v.gdb.Write(func(tx *gorm.DB) error {
		return tx.Save(&db.VTHashCache{
			SHA256:    sha256,
			Positives: stats.Malicious,
			Total:     t,
			FetchedAt: time.Now(),
		}).Error
	}); err != nil {
		v.log.Warn("virustotal: failed to cache result", "sha256", sha256, "err", err)
	}

	return stats.Malicious, t, "api", nil
}
