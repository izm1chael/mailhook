package handlers

import (
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"gorm.io/gorm"

	"github.com/izm1chael/mailhook/auth"
	"github.com/izm1chael/mailhook/db"
	"github.com/izm1chael/mailhook/web"
)

// DashboardHandler serves the main overview page.
type DashboardHandler struct {
	gdb        *db.DB
	middleware *auth.Middleware
	log        *slog.Logger
}

// NewDashboardHandler creates a DashboardHandler.
func NewDashboardHandler(gdb *db.DB, middleware *auth.Middleware, log *slog.Logger) *DashboardHandler {
	return &DashboardHandler{gdb: gdb, middleware: middleware, log: log}
}

// buildScanFilters applies common query params to a GORM query and returns active filter values.
func buildScanFilters(r *http.Request, q *gorm.DB) (*gorm.DB, map[string]string) {
	applied := map[string]string{}
	if v := r.URL.Query().Get("verdict"); v != "" {
		q = q.Where("verdict = ?", strings.ToUpper(v))
		applied["verdict"] = v
	}
	if v := r.URL.Query().Get("q"); v != "" {
		pattern := "%" + escapeLike(v) + "%"
		q = q.Where("`from` LIKE ? OR subject LIKE ?", pattern, pattern)
		applied["q"] = v
	}
	if v := r.URL.Query().Get("from_date"); v != "" {
		if t, err := time.Parse("2006-01-02", v); err == nil {
			q = q.Where("created_at >= ?", t)
			applied["from_date"] = v
		}
	}
	if v := r.URL.Query().Get("to_date"); v != "" {
		if t, err := time.Parse("2006-01-02", v); err == nil {
			q = q.Where("created_at <= ?", t.Add(24*time.Hour-time.Second))
			applied["to_date"] = v
		}
	}
	return q, applied
}

// GetDashboard renders the dashboard with recent scans and summary stats.
func (h *DashboardHandler) GetDashboard(w http.ResponseWriter, r *http.Request) {
	csrfToken := csrfFromRequest(h.middleware, w, r)

	baseQ, applied := buildScanFilters(r, h.gdb.Model(&db.Scan{}))
	var recentScans []db.Scan
	baseQ.Order("created_at desc").Limit(100).Find(&recentScans)

	var total, quarantined, deleted int64
	h.gdb.Model(&db.Scan{}).Count(&total)
	h.gdb.Model(&db.Scan{}).Where("status = ?", db.StatusQuarantined).Count(&quarantined)
	h.gdb.Model(&db.Scan{}).Where("status = ?", db.StatusDeleted).Count(&deleted)

	since24h := time.Now().Add(-24 * time.Hour)
	var last24h int64
	h.gdb.Model(&db.Scan{}).Where("created_at > ?", since24h).Count(&last24h)

	web.Render(w, r, "dashboard.html", map[string]interface{}{
		"CSRFToken":      csrfToken,
		"Scans":          recentScans,
		"Total":          total,
		"Quarantined":    quarantined,
		"Deleted":        deleted,
		"Last24h":        last24h,
		"Page":           "dashboard",
		"Nav":            "dashboard",
		"Filters":        applied,
		"VerdictOptions": []string{"CLEAN", "SPAM", "PHISH", "MALWARE", "SUSPICIOUS"},
	})
}

// GetQuarantine renders the quarantine view.
func (h *DashboardHandler) GetQuarantine(w http.ResponseWriter, r *http.Request) {
	csrfToken := csrfFromRequest(h.middleware, w, r)

	page, limit := paginationParams(r, 50)
	offset := (page - 1) * limit

	baseQ := h.gdb.Model(&db.Scan{}).Where("status = ?", db.StatusQuarantined)
	baseQ, applied := buildScanFilters(r, baseQ)

	var total int64
	baseQ.Count(&total)

	var scans []db.Scan
	baseQ.Order("created_at desc").Limit(limit).Offset(offset).Find(&scans)

	web.Render(w, r, "quarantine.html", map[string]interface{}{
		"CSRFToken":      csrfToken,
		"Scans":          scans,
		"Total":          total,
		"Page":           page,
		"Limit":          limit,
		"Pages":          totalPages(total, limit),
		"Nav":            "quarantine",
		"Filters":        applied,
		"VerdictOptions": []string{"CLEAN", "SPAM", "PHISH", "MALWARE", "SUSPICIOUS"},
	})
}

// GetBackfill renders the historical scan results view.
func (h *DashboardHandler) GetBackfill(w http.ResponseWriter, r *http.Request) {
	csrfToken := csrfFromRequest(h.middleware, w, r)

	page, limit := paginationParams(r, 50)
	offset := (page - 1) * limit

	baseQ := h.gdb.Model(&db.Scan{}).Where("source = ?", db.SourceBackfill)
	baseQ, applied := buildScanFilters(r, baseQ)

	var total int64
	baseQ.Count(&total)

	var scans []db.Scan
	baseQ.Order("created_at desc").Limit(limit).Offset(offset).Find(&scans)

	web.Render(w, r, "backfill.html", map[string]interface{}{
		"CSRFToken":      csrfToken,
		"Scans":          scans,
		"Total":          total,
		"Page":           page,
		"Limit":          limit,
		"Pages":          totalPages(total, limit),
		"Nav":            "backfill",
		"Filters":        applied,
		"VerdictOptions": []string{"CLEAN", "SPAM", "PHISH", "MALWARE", "SUSPICIOUS"},
	})
}

// GetAuditLog renders the audit log viewer.
func (h *DashboardHandler) GetAuditLog(w http.ResponseWriter, r *http.Request) {
	csrfToken := csrfFromRequest(h.middleware, w, r)
	page, limit := paginationParams(r, 100)
	offset := (page - 1) * limit

	type auditRow struct {
		db.AuditLog
		Subject string
		From    string
	}
	var rows []auditRow
	q := h.gdb.Table("audit_logs").
		Select("audit_logs.*, scans.subject, scans.`from`").
		Joins("LEFT JOIN scans ON scans.id = audit_logs.scan_id").
		Order("audit_logs.created_at desc")

	if v := r.URL.Query().Get("action"); v != "" {
		q = q.Where("audit_logs.action = ?", strings.ToUpper(v))
	}
	if v := r.URL.Query().Get("from_date"); v != "" {
		if t, err := time.Parse("2006-01-02", v); err == nil {
			q = q.Where("audit_logs.created_at >= ?", t)
		}
	}
	if v := r.URL.Query().Get("to_date"); v != "" {
		if t, err := time.Parse("2006-01-02", v); err == nil {
			q = q.Where("audit_logs.created_at <= ?", t.Add(24*time.Hour-time.Second))
		}
	}

	var total int64
	q.Count(&total)
	q.Limit(limit).Offset(offset).Scan(&rows)

	web.Render(w, r, "audit.html", map[string]interface{}{
		"CSRFToken":     csrfToken,
		"Rows":          rows,
		"Total":         total,
		"Page":          page,
		"Pages":         totalPages(total, limit),
		"ActionOptions": []string{"QUARANTINE", "RELEASE", "DELETE", "LEARN_HAM", "LEARN_SPAM", "RESCAN"},
		"Filters": map[string]string{
			"action":    r.URL.Query().Get("action"),
			"from_date": r.URL.Query().Get("from_date"),
			"to_date":   r.URL.Query().Get("to_date"),
		},
		"Nav": "audit",
	})
}

// GetStats renders the statistics page.
func (h *DashboardHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	csrfToken := csrfFromRequest(h.middleware, w, r)

	since30d := time.Now().AddDate(0, 0, -30)

	type verdictCount struct {
		Verdict string
		Count   int
	}
	var verdictCounts []verdictCount
	h.gdb.Model(&db.Scan{}).
		Select("verdict, count(*) as count").
		Where("created_at > ?", since30d).
		Group("verdict").
		Scan(&verdictCounts)

	type senderCount struct {
		From  string
		Count int
	}
	var topSenders []senderCount
	h.gdb.Model(&db.Scan{}).
		Select("`from`, count(*) as count").
		Where("created_at > ?", since30d).
		Group("`from`").Order("count desc").Limit(10).
		Scan(&topSenders)

	var dailyStats []db.DailyStat
	h.gdb.Where("date >= ?", since30d.Format("2006-01-02")).
		Order("date asc").
		Find(&dailyStats)

	// Flow data: per-verdict × per-status counts for the Sankey diagram.
	type flowStat struct {
		Verdict string
		Status  string
		Count   int
	}
	var flowData []flowStat
	h.gdb.Model(&db.Scan{}).
		Select("verdict, status, count(*) as count").
		Where("created_at > ?", since30d).
		Group("verdict, status").
		Scan(&flowData)

	web.Render(w, r, "stats.html", map[string]interface{}{
		"CSRFToken":     csrfToken,
		"VerdictCounts": verdictCounts,
		"TopSenders":    topSenders,
		"DailyStats":    dailyStats,
		"FlowData":      flowData,
		"Nav":           "stats",
	})
}

// csrfFromRequest returns the nonce portion of the signed CSRF cookie to embed in the
// page. The cookie value is "nonce.HMAC" — only the nonce is submitted by the client
// as X-CSRF-Token. If no valid signed cookie exists, a new one is issued.
func csrfFromRequest(mw *auth.Middleware, w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie("mailhook_csrf"); err == nil && c.Value != "" {
		if parts := strings.SplitN(c.Value, ".", 2); len(parts) == 2 {
			return parts[0]
		}
	}
	return mw.SetCSRFCookie(w)
}

func paginationParams(r *http.Request, defaultLimit int) (page, limit int) {
	page = 1
	limit = defaultLimit
	if v := r.URL.Query().Get("page"); v != "" {
		if p, err := parsePositiveInt(v); err == nil && p <= 10000 {
			page = p
		}
	}
	if v := r.URL.Query().Get("limit"); v != "" {
		if l, err := parsePositiveInt(v); err == nil && l <= 200 {
			limit = l
		}
	}
	return
}

func totalPages(total int64, limit int) int {
	if limit <= 0 {
		return 1
	}
	pages := int(total) / limit
	if int(total)%limit > 0 {
		pages++
	}
	if pages == 0 {
		return 1
	}
	return pages
}

func parsePositiveInt(s string) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 {
		return 0, strconv.ErrSyntax
	}
	return n, nil
}

func escapeLike(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `%`, `\%`)
	s = strings.ReplaceAll(s, `_`, `\_`)
	return s
}
