package handlers

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/izm1chael/mailhook/db"
)

// Pinger is satisfied by any scanner that exposes a Ping method.
type Pinger interface {
	Ping(ctx context.Context) error
}

// DBChecker can run a SQLite integrity check.
type DBChecker interface {
	IntegrityCheck() error
}

// FeedStatsProvider exposes per-feed entry counts.
type FeedStatsProvider interface {
	FeedStats() (counts map[string]int, lastLoaded time.Time)
}

// YARARuleProvider exposes the current rule count and last load time.
type YARARuleProvider interface {
	RuleCount() int
	LastLoaded() time.Time
}

// HealthHandler returns full component health as JSON (spec §17).
type HealthHandler struct {
	gdb     *db.DB
	rspamd  Pinger
	clamav  Pinger
	feeds   FeedStatsProvider
	yara    YARARuleProvider
	version string
	startAt time.Time
	log     *slog.Logger

	mu           sync.Mutex
	cachedResp   []byte
	cachedStatus int
	cachedAt     time.Time
	cacheMaxAge  time.Duration
}

// NewHealthHandler creates a HealthHandler with a 10-second response cache.
func NewHealthHandler(
	gdb *db.DB,
	rspamd, clamav Pinger,
	feeds FeedStatsProvider,
	yara YARARuleProvider,
	version string,
	log *slog.Logger,
) *HealthHandler {
	return &HealthHandler{
		gdb:         gdb,
		rspamd:      rspamd,
		clamav:      clamav,
		feeds:       feeds,
		yara:        yara,
		version:     version,
		startAt:     time.Now(),
		cacheMaxAge: 10 * time.Second,
		log:         log,
	}
}

type healthComponent struct {
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

type yaraHealthComponent struct {
	Status     string    `json:"status"`
	RuleCount  int       `json:"rule_count"`
	LastLoaded time.Time `json:"last_loaded,omitempty"`
}

type feedsHealthComponent struct {
	Status string         `json:"status"`
	Counts map[string]int `json:"counts"`
}

type healthComponents struct {
	Database healthComponent      `json:"database"`
	Rspamd   healthComponent      `json:"rspamd"`
	ClamAV   healthComponent      `json:"clamav"`
	YARA     yaraHealthComponent  `json:"yara"`
	Feeds    feedsHealthComponent `json:"feeds"`
}

type statsToday struct {
	Total      int `json:"total"`
	Clean      int `json:"clean"`
	Spam       int `json:"spam"`
	Phish      int `json:"phish"`
	Malware    int `json:"malware"`
	Suspicious int `json:"suspicious"`
}

type healthResponse struct {
	Status        string           `json:"status"`
	Version       string           `json:"version"`
	UptimeSeconds int64            `json:"uptime_seconds"`
	Components    healthComponents `json:"components"`
	StatsToday    statsToday       `json:"stats_today"`
}

// GetLiveness handles GET /healthz.
// Always returns 200 — used as the container HEALTHCHECK endpoint.
// No auth required; no dependency checks so it never causes restart loops.
func (h *HealthHandler) GetLiveness(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"alive"}`)) // nosemgrep: go.lang.security.audit.xss.no-direct-write-to-responsewriter.no-direct-write-to-responsewriter
}

// GetHealth handles GET /health (auth-gated).
// Returns HTTP 503 when any critical component (db, rspamd, clamav) is unhealthy.
func (h *HealthHandler) GetHealth(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	if time.Since(h.cachedAt) < h.cacheMaxAge && h.cachedResp != nil {
		cached := h.cachedResp
		cachedStatus := h.cachedStatus
		h.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(cachedStatus)
		w.Write(cached) // nosemgrep: go.lang.security.audit.xss.no-direct-write-to-responsewriter.no-direct-write-to-responsewriter
		return
	}
	h.mu.Unlock()

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	var components healthComponents
	allHealthy := true
	var mu sync.Mutex

	check := func(name string, fn func() error) healthComponent {
		if err := fn(); err != nil {
			h.log.Error("health check failed", "component", name, "err", err)
			mu.Lock()
			allHealthy = false
			mu.Unlock()
			return healthComponent{Status: "unhealthy", Error: "component unreachable"}
		}
		return healthComponent{Status: "healthy"}
	}

	// Database check uses a cheap SELECT 1 probe so /health polling doesn't
	// trigger an O(DB-size) integrity_check on every call.
	components.Database = check("database", h.gdb.QuickCheck)

	// Rspamd and ClamAV are network calls — run concurrently.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		result := check("rspamd", func() error { return h.rspamd.Ping(ctx) })
		mu.Lock()
		components.Rspamd = result
		mu.Unlock()
	}()
	go func() {
		defer wg.Done()
		result := check("clamav", func() error { return h.clamav.Ping(ctx) })
		mu.Lock()
		components.ClamAV = result
		mu.Unlock()
	}()
	wg.Wait()

	components.YARA = yaraHealthComponent{
		Status:     "healthy",
		RuleCount:  h.yara.RuleCount(),
		LastLoaded: h.yara.LastLoaded(),
	}

	feedCounts, _ := h.feeds.FeedStats()
	if feedCounts == nil {
		feedCounts = map[string]int{}
	}
	components.Feeds = feedsHealthComponent{Status: "healthy", Counts: feedCounts}

	today := time.Now().Format("2006-01-02")
	var stat db.DailyStat
	h.gdb.Where("date = ?", today).First(&stat)
	st := statsToday{
		Total:      stat.Total,
		Clean:      stat.Clean,
		Spam:       stat.Spam,
		Phish:      stat.Phish,
		Malware:    stat.Malware,
		Suspicious: stat.Suspicious,
	}

	status := "healthy"
	httpStatus := http.StatusOK
	if !allHealthy {
		status = "degraded"
		httpStatus = http.StatusServiceUnavailable
	}

	resp := healthResponse{
		Status:        status,
		Version:       h.version,
		UptimeSeconds: int64(time.Since(h.startAt).Seconds()),
		Components:    components,
		StatsToday:    st,
	}
	b, _ := json.Marshal(resp)

	h.mu.Lock()
	h.cachedResp = b
	h.cachedStatus = httpStatus
	h.cachedAt = time.Now()
	h.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatus)
	w.Write(b) // nosemgrep: go.lang.security.audit.xss.no-direct-write-to-responsewriter.no-direct-write-to-responsewriter
}
