package handlers

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/izm1chael/mailhook/auth"
	"github.com/izm1chael/mailhook/db"
	"github.com/izm1chael/mailhook/web"
)

var (
	emailRe  = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]{2,}$`)
	domainRe = regexp.MustCompile(`^@?[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$`)
)

const bulkImportMaxBytes = 1 << 20  // 1 MB
const bulkImportMaxLines = 10_000

// AllowlistsHandler manages whitelist and blocklist CRUD operations.
type AllowlistsHandler struct {
	gdb        *db.DB
	middleware *auth.Middleware
	log        *slog.Logger
}

// NewAllowlistsHandler creates an AllowlistsHandler.
func NewAllowlistsHandler(gdb *db.DB, middleware *auth.Middleware, log *slog.Logger) *AllowlistsHandler {
	return &AllowlistsHandler{gdb: gdb, middleware: middleware, log: log}
}

// GetAllowlists renders the allowlists management page with current entries.
func (h *AllowlistsHandler) GetAllowlists(w http.ResponseWriter, r *http.Request) {
	csrfToken := csrfFromRequest(h.middleware, w, r)

	var whitelist []db.Whitelist
	h.gdb.Order("added_at desc").Find(&whitelist)

	var blocklist []db.Blocklist
	h.gdb.Order("added_at desc").Find(&blocklist)

	web.Render(w, r, "allowlists.html", map[string]interface{}{
		"CSRFToken": csrfToken,
		"Whitelist": whitelist,
		"Blocklist": blocklist,
		"Nav":       "allowlists",
	})
}

// ListWhitelist handles GET /api/whitelist
func (h *AllowlistsHandler) ListWhitelist(w http.ResponseWriter, r *http.Request) {
	var entries []db.Whitelist
	h.gdb.Order("added_at desc").Find(&entries)
	respondJSON(w, http.StatusOK, entries)
}

// AddWhitelist handles POST /api/whitelist
func (h *AllowlistsHandler) AddWhitelist(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Entry      string `json:"entry"`
		BypassScan bool   `json:"bypass_scan"`
		Reason     string `json:"reason"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Entry = strings.ToLower(strings.TrimSpace(req.Entry))
	if req.Entry == "" {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "entry must not be empty"})
		return
	}
	entryType, err := detectEntryType(req.Entry)
	if err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	entry := db.Whitelist{
		Entry:       req.Entry,
		EntryType:   entryType,
		BypassScan:  req.BypassScan,
		AddedAt:     time.Now(),
		AddedReason: req.Reason,
	}
	if err := h.gdb.Write(func(tx *gorm.DB) error { return tx.Create(&entry).Error }); err != nil {
		respondJSON(w, http.StatusConflict, map[string]string{"error": "entry already exists or db error"})
		return
	}
	h.auditList(r, db.ActionWhitelist, entry.Entry)
	respondJSON(w, http.StatusCreated, entry)
}

// DeleteWhitelist handles DELETE /api/whitelist/{id}
func (h *AllowlistsHandler) DeleteWhitelist(w http.ResponseWriter, r *http.Request) {
	id, ok := scanIDFromPath(w, r)
	if !ok {
		return
	}
	var result *gorm.DB
	h.gdb.Write(func(tx *gorm.DB) error { //nolint:errcheck
		result = tx.Delete(&db.Whitelist{}, id)
		return result.Error
	})
	if result == nil || result.RowsAffected == 0 {
		respondJSON(w, http.StatusNotFound, map[string]string{"error": "entry not found"})
		return
	}
	respondJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// ListBlocklist handles GET /api/blocklist
func (h *AllowlistsHandler) ListBlocklist(w http.ResponseWriter, r *http.Request) {
	var entries []db.Blocklist
	h.gdb.Order("added_at desc").Find(&entries)
	respondJSON(w, http.StatusOK, entries)
}

// AddBlocklist handles POST /api/blocklist
func (h *AllowlistsHandler) AddBlocklist(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Entry  string `json:"entry"`
		Reason string `json:"reason"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Entry = strings.ToLower(strings.TrimSpace(req.Entry))
	if req.Entry == "" {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "entry must not be empty"})
		return
	}
	entryType, err := detectEntryType(req.Entry)
	if err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	entry := db.Blocklist{
		Entry:       req.Entry,
		EntryType:   entryType,
		AddedAt:     time.Now(),
		AddedReason: req.Reason,
	}
	if err := h.gdb.Write(func(tx *gorm.DB) error { return tx.Create(&entry).Error }); err != nil {
		respondJSON(w, http.StatusConflict, map[string]string{"error": "entry already exists or db error"})
		return
	}
	h.auditList(r, db.ActionBlocklist, entry.Entry)
	respondJSON(w, http.StatusCreated, entry)
}

// DeleteBlocklist handles DELETE /api/blocklist/{id}
func (h *AllowlistsHandler) DeleteBlocklist(w http.ResponseWriter, r *http.Request) {
	id, ok := scanIDFromPath(w, r)
	if !ok {
		return
	}
	var result *gorm.DB
	h.gdb.Write(func(tx *gorm.DB) error { //nolint:errcheck
		result = tx.Delete(&db.Blocklist{}, id)
		return result.Error
	})
	if result == nil || result.RowsAffected == 0 {
		respondJSON(w, http.StatusNotFound, map[string]string{"error": "entry not found"})
		return
	}
	respondJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// BulkImport handles POST /api/allowlists/bulk-import
// Body: JSON {"list":"whitelist"|"blocklist","entries":"...\n...","bypass_scan":false}
func (h *AllowlistsHandler) BulkImport(w http.ResponseWriter, r *http.Request) {
	// Use a higher limit than decodeJSON's default — bulk payloads can be large.
	r.Body = http.MaxBytesReader(w, r.Body, bulkImportMaxBytes)
	var req struct {
		List       string `json:"list"`
		Entries    string `json:"entries"`
		BypassScan bool   `json:"bypass_scan"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON: " + err.Error()})
		return
	}
	if req.List != "whitelist" && req.List != "blocklist" {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "list must be whitelist or blocklist"})
		return
	}

	var skipped, lineCount int
	now := time.Now()
	var whitelists []db.Whitelist
	var blocklists []db.Blocklist

	scanner := bufio.NewScanner(bytes.NewBufferString(req.Entries))
	for scanner.Scan() {
		val := strings.ToLower(strings.TrimSpace(scanner.Text()))
		if val == "" || strings.HasPrefix(val, "#") {
			continue
		}
		lineCount++
		if lineCount > bulkImportMaxLines {
			respondJSON(w, http.StatusBadRequest, map[string]string{
				"error": fmt.Sprintf("import exceeds maximum of %d entries", bulkImportMaxLines),
			})
			return
		}
		entryType, err := detectEntryType(val)
		if err != nil {
			skipped++
			continue
		}
		if req.List == "whitelist" {
			whitelists = append(whitelists, db.Whitelist{
				Entry: val, EntryType: entryType,
				BypassScan: req.BypassScan,
				AddedAt:    now,
			})
		} else {
			blocklists = append(blocklists, db.Blocklist{
				Entry: val, EntryType: entryType,
				AddedAt: now,
			})
		}
	}

	// Insert all valid entries in a single batched transaction to avoid
	// N individual fsync'd commits for large imports (F-034).
	// Use RowsAffected (not len(slice)) so duplicate entries are reported
	// as skipped rather than imported.
	onConflict := clause.OnConflict{DoNothing: true}
	const batchSize = 500
	var totalImported int64
	if len(whitelists) > 0 {
		if err := h.gdb.Write(func(tx *gorm.DB) error {
			res := tx.Clauses(onConflict).CreateInBatches(whitelists, batchSize)
			totalImported += res.RowsAffected
			return res.Error
		}); err != nil {
			respondJSON(w, http.StatusInternalServerError, map[string]string{"error": "import failed: " + err.Error()})
			return
		}
	}
	if len(blocklists) > 0 {
		if err := h.gdb.Write(func(tx *gorm.DB) error {
			res := tx.Clauses(onConflict).CreateInBatches(blocklists, batchSize)
			totalImported += res.RowsAffected
			return res.Error
		}); err != nil {
			respondJSON(w, http.StatusInternalServerError, map[string]string{"error": "import failed: " + err.Error()})
			return
		}
	}

	// skipped = invalid-type lines + duplicate entries (ON CONFLICT DO NOTHING)
	duplicates := int64(len(whitelists)+len(blocklists)) - totalImported
	respondJSON(w, http.StatusOK, map[string]int{"imported": int(totalImported), "skipped": skipped + int(duplicates)})
}

func (h *AllowlistsHandler) auditList(r *http.Request, action, value string) {
	actor := actorFromRequest(r)
	h.gdb.Write(func(tx *gorm.DB) error { //nolint:errcheck
		return tx.Create(&db.AuditLog{
			Action:    action,
			Actor:     actor,
			Note:      value,
			CreatedAt: time.Now(),
		}).Error
	})
}

// detectEntryType returns the entry type ("address" or "domain") and validates the format.
// Returns an error if the entry is neither a valid email address nor a valid domain.
func detectEntryType(entry string) (string, error) {
	if strings.Contains(entry, "@") && !strings.HasPrefix(entry, "@") {
		if !emailRe.MatchString(entry) {
			return "", fmt.Errorf("invalid email address: %q", entry)
		}
		return "address", nil
	}
	if !domainRe.MatchString(entry) {
		return "", fmt.Errorf("invalid domain: %q", entry)
	}
	return "domain", nil
}

const jsonBodyMaxBytes = 64 * 1024 // 64 KB default limit for JSON API endpoints

// decodeJSON decodes the request body as JSON into v, enforcing a 64 KB body limit.
// On error it writes a 400 response and returns false.
func decodeJSON(w http.ResponseWriter, r *http.Request, v interface{}) bool {
	r.Body = http.MaxBytesReader(w, r.Body, jsonBodyMaxBytes)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON: " + err.Error()})
		return false
	}
	return true
}
