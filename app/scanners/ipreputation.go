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

	"github.com/izm1chael/mailhook/db"
	"github.com/izm1chael/mailhook/pipeline"
	"gorm.io/gorm"
)

// IPReputation queries AbuseIPDB for the sending IP reputation.
// Results are cached in SQLite to avoid redundant API calls.
type IPReputation struct {
	mu       sync.RWMutex
	apiKey   string
	enabled  bool
	gdb      *db.DB
	cacheTTL time.Duration
	client   *http.Client
	log      *slog.Logger
}

type abuseIPDBResponse struct {
	Data struct {
		AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
		TotalReports         int    `json:"totalReports"`
		CountryCode          string `json:"countryCode"`
		ISP                  string `json:"isp"`
	} `json:"data"`
}

// NewIPReputation creates an IPReputation scanner. If apiKey is empty the scanner
// returns "skip" on every call without making any network requests.
func NewIPReputation(apiKey string, gdb *db.DB, log *slog.Logger) *IPReputation {
	return &IPReputation{
		apiKey:   apiKey,
		enabled:  true,
		gdb:      gdb,
		cacheTTL: 24 * time.Hour,
		client:   &http.Client{Timeout: 10 * time.Second},
		log:      log,
	}
}

// SetEnabled enables or disables the scanner at runtime.
func (r *IPReputation) SetEnabled(b bool) { r.mu.Lock(); r.enabled = b; r.mu.Unlock() }

// IsEnabled reports whether the scanner is currently enabled.
func (r *IPReputation) IsEnabled() bool { r.mu.RLock(); defer r.mu.RUnlock(); return r.enabled }

func (r *IPReputation) Name() string { return "ipreputation" }

// SetAPIKey updates the API key at runtime without restarting.
func (r *IPReputation) SetAPIKey(key string) {
	r.mu.Lock()
	r.apiKey = key
	r.mu.Unlock()
}

// Scan checks each public sending IP against AbuseIPDB (with SQLite caching).
func (r *IPReputation) Scan(ctx context.Context, email *pipeline.Email) pipeline.ScanResult {
	r.mu.RLock()
	apiKey := r.apiKey
	enabled := r.enabled
	r.mu.RUnlock()
	if !enabled {
		return pipeline.ScanResult{Scanner: r.Name(), Verdict: "skip", Detail: "disabled"}
	}
	if apiKey == "" || len(email.SenderIPs) == 0 {
		return pipeline.ScanResult{Scanner: r.Name(), Verdict: "skip"}
	}

	ip := email.SenderIPs[0].String()

	result, err := r.lookup(ctx, ip, apiKey)
	if err != nil {
		r.log.Warn("abuseipdb lookup failed", "ip", ip, "err", err)
		return pipeline.ScanResult{Scanner: r.Name(), Verdict: "skip", Detail: "unavailable"}
	}

	matchData, _ := json.Marshal(result)
	detail := fmt.Sprintf("IP %s abuse score %d/100 (source: %s)", ip, result.AbuseScore, result.Source)

	switch {
	case result.AbuseScore >= 75:
		return pipeline.ScanResult{Scanner: r.Name(), Verdict: "malicious", Score: float64(result.AbuseScore), Detail: detail, Matches: matchData}
	case result.AbuseScore >= 25:
		return pipeline.ScanResult{Scanner: r.Name(), Verdict: "suspicious", Score: float64(result.AbuseScore), Detail: detail, Matches: matchData}
	default:
		return pipeline.ScanResult{Scanner: r.Name(), Verdict: "clean", Score: float64(result.AbuseScore), Detail: detail, Matches: matchData}
	}
}

func (r *IPReputation) lookup(ctx context.Context, ip string, apiKey string) (db.IPReputationResult, error) {
	// Check cache first
	var cached db.IPReputationCache
	if err := r.gdb.Where("ip = ? AND expires_at > ?", ip, time.Now()).First(&cached).Error; err == nil {
		return db.IPReputationResult{
			IP:           ip,
			AbuseScore:   cached.AbuseScore,
			TotalReports: cached.TotalReports,
			CountryCode:  cached.CountryCode,
			ISP:          cached.ISP,
			Source:       "cache",
		}, nil
	}

	// API call
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://api.abuseipdb.com/api/v2/check", nil)
	if err != nil {
		return db.IPReputationResult{}, err
	}
	q := req.URL.Query()
	q.Set("ipAddress", ip)
	q.Set("maxAgeInDays", "90")
	req.URL.RawQuery = q.Encode()
	req.Header.Set("Key", apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := r.client.Do(req)
	if err != nil {
		return db.IPReputationResult{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return db.IPReputationResult{}, fmt.Errorf("abuseipdb returned HTTP %d", resp.StatusCode)
	}

	var apiResp abuseIPDBResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64*1024)).Decode(&apiResp); err != nil {
		return db.IPReputationResult{}, fmt.Errorf("decode: %w", err)
	}

	if err := r.gdb.Write(func(tx *gorm.DB) error {
		return tx.Save(&db.IPReputationCache{
			IP:           ip,
			AbuseScore:   apiResp.Data.AbuseConfidenceScore,
			TotalReports: apiResp.Data.TotalReports,
			CountryCode:  apiResp.Data.CountryCode,
			ISP:          apiResp.Data.ISP,
			FetchedAt:    time.Now(),
			ExpiresAt:    time.Now().Add(r.cacheTTL),
		}).Error
	}); err != nil {
		r.log.Warn("ipreputation: failed to cache result", "ip", ip, "err", err)
	}

	return db.IPReputationResult{
		IP:           ip,
		AbuseScore:   apiResp.Data.AbuseConfidenceScore,
		TotalReports: apiResp.Data.TotalReports,
		CountryCode:  apiResp.Data.CountryCode,
		ISP:          apiResp.Data.ISP,
		Source:       "api",
	}, nil
}
