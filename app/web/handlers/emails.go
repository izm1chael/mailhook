package handlers

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/izm1chael/mailhook/db"
	"github.com/izm1chael/mailhook/storage"
	"github.com/izm1chael/mailhook/util"
)

// EmailsHandler serves the email scan API endpoints.
type EmailsHandler struct {
	gdb   *db.DB
	store *storage.Store
}

// NewEmailsHandler creates an EmailsHandler.
func NewEmailsHandler(gdb *db.DB, store *storage.Store) *EmailsHandler {
	return &EmailsHandler{gdb: gdb, store: store}
}

// ListScans handles GET /api/scans
// Supports query params: status, verdict, account, from, subject, page, limit
func (h *EmailsHandler) ListScans(w http.ResponseWriter, r *http.Request) {
	page, limit := paginationParams(r, 50)
	offset := (page - 1) * limit

	q := h.gdb.Model(&db.Scan{}).Order("created_at desc")

	if status := r.URL.Query().Get("status"); status != "" {
		q = q.Where("status = ?", strings.ToUpper(status))
	}
	if verdict := r.URL.Query().Get("verdict"); verdict != "" {
		q = q.Where("verdict = ?", strings.ToUpper(verdict))
	}
	if account := r.URL.Query().Get("account"); account != "" {
		q = q.Where("account_name = ?", account)
	}
	if from := r.URL.Query().Get("from"); from != "" {
		q = q.Where("`from` LIKE ?", "%"+escapeLike(from)+"%")
	}
	if subject := r.URL.Query().Get("subject"); subject != "" {
		q = q.Where("subject LIKE ?", "%"+escapeLike(subject)+"%")
	}

	var total int64
	q.Count(&total)

	var scans []db.Scan
	q.Limit(limit).Offset(offset).Find(&scans)

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"total": total,
		"page":  page,
		"limit": limit,
		"scans": scans,
	})
}

// GetScan handles GET /api/scans/{id}
func (h *EmailsHandler) GetScan(w http.ResponseWriter, r *http.Request) {
	id, ok := scanIDFromPath(w, r)
	if !ok {
		return
	}

	var scan db.Scan
	if err := h.gdb.First(&scan, id).Error; err != nil {
		respondJSON(w, http.StatusNotFound, map[string]string{"error": "scan not found"})
		return
	}

	respondJSON(w, http.StatusOK, scan)
}

// DownloadEML handles GET /api/eml/{id} — streams the raw EML file.
func (h *EmailsHandler) DownloadEML(w http.ResponseWriter, r *http.Request) {
	id, ok := scanIDFromPath(w, r)
	if !ok {
		return
	}

	var scan db.Scan
	if err := h.gdb.First(&scan, id).Error; err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if scan.EMLPath == "" {
		http.Error(w, "EML not stored", http.StatusNotFound)
		return
	}

	raw, err := h.store.Read(scan.EMLPath)
	if err != nil {
		http.Error(w, "EML read error", http.StatusInternalServerError)
		return
	}

	filename := util.SHA256Hex([]byte(scan.MessageID)) + ".eml"
	w.Header().Set("Content-Type", "message/rfc822")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+filename+"\"")
	w.Header().Set("Content-Length", strconv.Itoa(len(raw)))
	w.WriteHeader(http.StatusOK)
	w.Write(raw) // nosemgrep: go.lang.security.audit.xss.no-direct-write-to-responsewriter.no-direct-write-to-responsewriter
}

// previewTmpl wraps already-sanitized HTML in a minimal sandboxed page.
// Using template.HTML tells html/template the content is already safe.
var previewTmpl = template.Must(template.New("preview").Parse(`<!DOCTYPE html>
<html><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'none'; style-src 'unsafe-inline'">
<style>body{font-family:sans-serif;font-size:14px;padding:8px;word-break:break-word}</style>
</head><body>{{.Body}}</body></html>`))

// PreviewHTML handles GET /api/preview/{id} — returns sanitized HTML for iframe display.
func (h *EmailsHandler) PreviewHTML(w http.ResponseWriter, r *http.Request) {
	id, ok := scanIDFromPath(w, r)
	if !ok {
		return
	}

	var scan db.Scan
	if err := h.gdb.First(&scan, id).Error; err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	var body template.HTML
	if scan.EMLPath != "" {
		raw, err := h.store.Read(scan.EMLPath)
		if err == nil {
			// ExtractAndSanitizeHTML sanitizes with bluemonday UGCPolicy (allows common formatting tags; strips scripts, iframes, and event handlers).
			body = template.HTML(util.ExtractAndSanitizeHTML(raw)) // #nosec G203 -- input sanitized by bluemonday UGCPolicy (scripts/iframes/handlers stripped). nosemgrep: go.lang.security.audit.xss.template-html-does-not-escape.unsafe-template-type
		}
	}
	if body == "" {
		body = "<p><em>No content available.</em></p>"
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Frame-Options", "SAMEORIGIN")
	// Override the global nonce-based CSP: the preview document is self-contained
	// with no external resources; inline styles are required for email rendering.
	w.Header().Set("Content-Security-Policy",
		"default-src 'none'; script-src 'none'; style-src 'unsafe-inline'; img-src 'none';")
	previewTmpl.Execute(w, map[string]interface{}{"Body": body})
}

// Export handles GET /api/export — streams matching scans as a CSV download.
func (h *EmailsHandler) Export(w http.ResponseWriter, r *http.Request) {
	q := h.gdb.Model(&db.Scan{})
	if v := r.URL.Query().Get("verdict"); v != "" {
		q = q.Where("verdict = ?", strings.ToUpper(v))
	}
	if v := r.URL.Query().Get("status"); v != "" {
		q = q.Where("status = ?", strings.ToUpper(v))
	}
	if v := r.URL.Query().Get("q"); v != "" {
		pattern := "%" + escapeLike(v) + "%"
		q = q.Where("`from` LIKE ? OR subject LIKE ?", pattern, pattern)
	}
	if v := r.URL.Query().Get("from_date"); v != "" {
		if t, err := time.Parse("2006-01-02", v); err == nil {
			q = q.Where("created_at >= ?", t)
		}
	}
	if v := r.URL.Query().Get("to_date"); v != "" {
		if t, err := time.Parse("2006-01-02", v); err == nil {
			q = q.Where("created_at <= ?", t.Add(24*time.Hour-time.Second))
		}
	}

	// Default to last 90 days when no date window is specified to prevent OOM on large tables.
	if r.URL.Query().Get("from_date") == "" && r.URL.Query().Get("to_date") == "" {
		q = q.Where("created_at >= ?", time.Now().AddDate(0, 0, -90))
	}

	fname := "mailhook-export-" + time.Now().Format("2006-01-02") + ".csv"
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", `attachment; filename="`+fname+`"`)

	rows, err := q.Order("created_at desc").Limit(5000).Rows()
	if err != nil {
		http.Error(w, "export failed", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	cw := csv.NewWriter(w)
	cw.Write([]string{"ID", "Received", "From", "To", "Subject", "Verdict", "RspamdScore", "SPF", "DKIM", "DMARC", "ClamAV", "Status", "ActionedBy", "ActionedAt"}) //nolint:errcheck
	for rows.Next() {
		var s db.Scan
		if err := h.gdb.ScanRows(rows, &s); err != nil {
			continue
		}
		actionedAt := ""
		if s.ActionedAt != nil {
			actionedAt = s.ActionedAt.Format(time.RFC3339)
		}
		cw.Write([]string{ //nolint:errcheck
			fmt.Sprintf("%d", s.ID),
			s.CreatedAt.Format(time.RFC3339),
			sanitizeCSVField(s.From), sanitizeCSVField(s.To), sanitizeCSVField(s.Subject),
			s.Verdict,
			fmt.Sprintf("%.2f", s.RspamdScore),
			s.SPFResult, s.DKIMResult, s.DMARCResult,
			s.ClamAVStatus,
			s.Status, sanitizeCSVField(s.ActionedBy), actionedAt,
		})
	}
	cw.Flush()
}

// sanitizeCSVField prefixes cells that start with formula-trigger characters so
// spreadsheet apps don't evaluate them as formulas (CSV injection prevention).
func sanitizeCSVField(s string) string {
	if len(s) > 0 && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

// DefangURL handles GET /api/defang?url=<raw>
// Returns a defanged representation safe for display in reports.
func DefangURL(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("url")
	if raw == "" {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "url query param required"})
		return
	}
	out := util.DefangURL(raw)
	respondJSON(w, http.StatusOK, map[string]string{"defanged": out})
}

// respondJSON writes v as JSON with the given status code.
func respondJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// scanIDFromPath extracts the numeric ID from the last path segment.
func scanIDFromPath(w http.ResponseWriter, r *http.Request) (uint, bool) {
	parts := strings.Split(strings.TrimSuffix(r.URL.Path, "/"), "/")
	if len(parts) == 0 {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "missing id"})
		return 0, false
	}
	n, err := strconv.ParseUint(parts[len(parts)-1], 10, 64)
	if err != nil || n == 0 {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return 0, false
	}
	return uint(n), true
}
