package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"gorm.io/gorm"

	"github.com/izm1chael/mailhook/auth"
	"github.com/izm1chael/mailhook/db"
	"github.com/izm1chael/mailhook/storage"
)

// IMAPActions is the per-account interface for IMAP mutations.
type IMAPActions interface {
	MoveToQuarantine(ctx context.Context, mailbox string, uid uint32) (uint32, string, error)
	ReleaseToInbox(ctx context.Context, uid uint32) error
	DeleteMessage(ctx context.Context, mailbox string, uid uint32) error
	BulkReleaseToInbox(ctx context.Context, uids []uint32) error
	BulkDeleteMessages(ctx context.Context, mailbox string, uids []uint32) error
}

// RspamdLearner can submit EML bytes to Rspamd's Bayes classifier.
type RspamdLearner interface {
	LearnSpam(ctx context.Context, raw []byte) error
	LearnHam(ctx context.Context, raw []byte) error
}

// EmailProcessor re-runs the full pipeline on an existing EML.
type EmailProcessor interface {
	Process(ctx context.Context, accountName string, raw []byte, uid uint32, mailbox string)
}

// ActionsHandler handles all state-changing operations on scan records.
type ActionsHandler struct {
	gdb      *db.DB
	store    *storage.Store
	registry *AccountRegistry
	rspamd   RspamdLearner
	log      *slog.Logger
}

// NewActionsHandler creates an ActionsHandler.
func NewActionsHandler(
	gdb *db.DB,
	store *storage.Store,
	registry *AccountRegistry,
	rspamd RspamdLearner,
	log *slog.Logger,
) *ActionsHandler {
	return &ActionsHandler{
		gdb:      gdb,
		store:    store,
		registry: registry,
		rspamd:   rspamd,
		log:      log,
	}
}

// Release moves a quarantined message back to the inbox.
// POST /api/release/{id}
func (h *ActionsHandler) Release(w http.ResponseWriter, r *http.Request) {
	h.withScan(w, r, func(scan *db.Scan) {
		act, ok := h.registry.GetActions(scan.AccountName)
		if !ok {
			respondJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown account"})
			return
		}
		if err := act.ReleaseToInbox(r.Context(), scan.IMAPUID); err != nil {
			h.log.Error("release failed", "scan_id", scan.ID, "err", err)
			respondJSON(w, http.StatusInternalServerError, map[string]string{"error": "release failed"})
			return
		}
		if err := h.updateStatus(scan, db.StatusReleased, actorFromRequest(r)); err != nil {
			h.log.Error("updateStatus failed after release", "scan_id", scan.ID, "err", err)
			respondJSON(w, http.StatusInternalServerError, map[string]string{"error": "status update failed"})
			return
		}
		respondJSON(w, http.StatusOK, map[string]string{"status": "released"})
	})
}

// ReleaseAndLearn releases to inbox and teaches Rspamd this is ham.
// POST /api/release-learn/{id}
func (h *ActionsHandler) ReleaseAndLearn(w http.ResponseWriter, r *http.Request) {
	h.withScan(w, r, func(scan *db.Scan) {
		act, ok := h.registry.GetActions(scan.AccountName)
		if !ok {
			respondJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown account"})
			return
		}
		if err := act.ReleaseToInbox(r.Context(), scan.IMAPUID); err != nil {
			h.log.Error("release failed", "scan_id", scan.ID, "err", err)
			respondJSON(w, http.StatusInternalServerError, map[string]string{"error": "release failed"})
			return
		}
		// Best-effort learn — don't fail the release if Rspamd is down
		if raw, err := h.store.Read(scan.EMLPath); err == nil {
			if lerr := h.rspamd.LearnHam(r.Context(), raw); lerr != nil {
				h.log.Warn("learn ham failed", "scan_id", scan.ID, "err", lerr)
			}
		}
		if err := h.updateStatus(scan, db.StatusLearnedHam, actorFromRequest(r)); err != nil {
			h.log.Error("updateStatus failed after release-learn", "scan_id", scan.ID, "err", err)
			respondJSON(w, http.StatusInternalServerError, map[string]string{"error": "status update failed"})
			return
		}
		respondJSON(w, http.StatusOK, map[string]string{"status": "released_learned_ham"})
	})
}

// Delete permanently removes a message from IMAP and marks the record deleted.
// POST /api/delete/{id}
func (h *ActionsHandler) Delete(w http.ResponseWriter, r *http.Request) {
	h.withScan(w, r, func(scan *db.Scan) {
		act, ok := h.registry.GetActions(scan.AccountName)
		if !ok {
			respondJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown account"})
			return
		}
		if err := act.DeleteMessage(r.Context(), scan.IMAPMailbox, scan.IMAPUID); err != nil {
			h.log.Error("delete failed", "scan_id", scan.ID, "err", err)
			respondJSON(w, http.StatusInternalServerError, map[string]string{"error": "delete failed"})
			return
		}
		if err := h.updateStatus(scan, db.StatusDeleted, actorFromRequest(r)); err != nil {
			h.log.Error("updateStatus failed after delete", "scan_id", scan.ID, "err", err)
			respondJSON(w, http.StatusInternalServerError, map[string]string{"error": "status update failed"})
			return
		}
		respondJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	})
}

// Quarantine moves a message from its current mailbox to the quarantine folder.
// Used to manually quarantine backfill findings or any inbox message.
// POST /api/quarantine/{id}
func (h *ActionsHandler) Quarantine(w http.ResponseWriter, r *http.Request) {
	h.withScan(w, r, func(scan *db.Scan) {
		act, ok := h.registry.GetActions(scan.AccountName)
		if !ok {
			respondJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown account"})
			return
		}
		newUID, newMailbox, err := act.MoveToQuarantine(r.Context(), scan.IMAPMailbox, scan.IMAPUID)
		if err != nil {
			h.log.Error("quarantine failed", "scan_id", scan.ID, "err", err)
			respondJSON(w, http.StatusInternalServerError, map[string]string{"error": "quarantine failed"})
			return
		}
		actor := actorFromRequest(r)
		now := time.Now()
		if writeErr := h.gdb.Write(func(tx *gorm.DB) error {
			updates := map[string]interface{}{
				"status":       db.StatusQuarantined,
				"actioned_by":  actor,
				"actioned_at":  now,
				"imap_mailbox": newMailbox,
			}
			if newUID > 0 {
				updates["imap_uid"] = newUID
				updates["account_uid"] = db.MakeAccountUID(scan.AccountName, newMailbox, newUID)
			}
			if err := tx.Model(scan).Updates(updates).Error; err != nil {
				return err
			}
			return tx.Create(&db.AuditLog{
				ScanID:    scan.ID,
				Action:    db.ActionQuarantine,
				Actor:     actor,
				Note:      "user-triggered quarantine",
				CreatedAt: now,
			}).Error
		}); writeErr != nil {
			h.log.Error("updateStatus failed after quarantine", "scan_id", scan.ID, "err", writeErr)
			respondJSON(w, http.StatusInternalServerError, map[string]string{"error": "status update failed"})
			return
		}
		respondJSON(w, http.StatusOK, map[string]string{"status": "quarantined"})
	})
}

// LearnSpam teaches Rspamd this message is spam without moving it.
// POST /api/learn-spam/{id}
func (h *ActionsHandler) LearnSpam(w http.ResponseWriter, r *http.Request) {
	h.withScan(w, r, func(scan *db.Scan) {
		if scan.EMLPath == "" {
			respondJSON(w, http.StatusBadRequest, map[string]string{"error": "no EML stored"})
			return
		}
		raw, err := h.store.Read(scan.EMLPath)
		if err != nil {
			respondJSON(w, http.StatusInternalServerError, map[string]string{"error": "read EML failed"})
			return
		}
		if err := h.rspamd.LearnSpam(r.Context(), raw); err != nil {
			h.log.Error("learn spam failed", "scan_id", scan.ID, "err", err)
			respondJSON(w, http.StatusInternalServerError, map[string]string{"error": "learn spam failed"})
			return
		}
		if err := h.updateStatus(scan, db.StatusLearnedSpam, actorFromRequest(r)); err != nil {
			h.log.Error("updateStatus failed after learn-spam", "scan_id", scan.ID, "err", err)
			respondJSON(w, http.StatusInternalServerError, map[string]string{"error": "status update failed"})
			return
		}
		respondJSON(w, http.StatusOK, map[string]string{"status": "learned_spam"})
	})
}

// Rescan re-runs the full pipeline on the stored EML and records a RESCAN audit entry.
// POST /api/rescan/{id}
func (h *ActionsHandler) Rescan(w http.ResponseWriter, r *http.Request) {
	h.withScan(w, r, func(scan *db.Scan) {
		if scan.EMLPath == "" {
			respondJSON(w, http.StatusBadRequest, map[string]string{"error": "no EML stored for this scan"})
			return
		}
		proc, ok := h.registry.GetProcessor(scan.AccountName)
		if !ok {
			respondJSON(w, http.StatusBadRequest, map[string]string{"error": "no pipeline for account"})
			return
		}
		raw, err := h.store.Read(scan.EMLPath)
		if err != nil {
			respondJSON(w, http.StatusInternalServerError, map[string]string{"error": "read EML failed"})
			return
		}
		h.gdb.Write(func(tx *gorm.DB) error { //nolint:errcheck
			return tx.Create(&db.AuditLog{
				ScanID:    scan.ID,
				Action:    db.ActionRescan,
				Actor:     actorFromRequest(r),
				CreatedAt: time.Now(),
			}).Error
		})
		// Run pipeline in background using the account-specific pipeline; caller gets immediate 202.
		// context.WithoutCancel inherits values (trace IDs) from the request but is not cancelled
		// when the HTTP response is written — without this, r.Context() would cancel immediately
		// and abort the scan before it does any work.
		go proc.Process(context.WithoutCancel(r.Context()), scan.AccountName, raw, scan.IMAPUID, scan.IMAPMailbox)
		respondJSON(w, http.StatusAccepted, map[string]string{"status": "rescan_queued"})
	})
}

// withScan loads a scan by ID from the URL path and calls fn.
func (h *ActionsHandler) withScan(w http.ResponseWriter, r *http.Request, fn func(*db.Scan)) {
	id, ok := scanIDFromPath(w, r)
	if !ok {
		return
	}
	var scan db.Scan
	if err := h.gdb.First(&scan, id).Error; err != nil {
		respondJSON(w, http.StatusNotFound, map[string]string{"error": "scan not found"})
		return
	}
	fn(&scan)
}

// updateStatus persists the new lifecycle status and records an audit log entry.
// Returns any DB error so callers can detect DB inconsistency after a successful IMAP action.
func (h *ActionsHandler) updateStatus(scan *db.Scan, status, actor string) error {
	now := time.Now()
	return h.gdb.Write(func(tx *gorm.DB) error {
		if err := tx.Model(scan).Updates(map[string]interface{}{
			"status":      status,
			"actioned_by": actor,
			"actioned_at": now,
		}).Error; err != nil {
			return err
		}
		return tx.Create(&db.AuditLog{
			ScanID:    scan.ID,
			Action:    status,
			Actor:     actor,
			CreatedAt: now,
		}).Error
	})
}

// updateStatus is a tx-scoped helper used by BulkAction to mutate status inside an existing write lock.
func updateStatus(tx *gorm.DB, scan *db.Scan, status, actor, note string) error {
	now := time.Now()
	if err := tx.Model(scan).Updates(map[string]interface{}{
		"status":      status,
		"actioned_by": actor,
		"actioned_at": now,
	}).Error; err != nil {
		return err
	}
	return tx.Create(&db.AuditLog{
		ScanID:    scan.ID,
		Action:    status,
		Actor:     actor,
		Note:      note,
		CreatedAt: now,
	}).Error
}

// imapOutcome carries the result of a single bulk IMAP operation back to the
// response goroutine so that succeeded/failed counts are accurate.
type imapOutcome struct {
	id     uint
	action string
	err    error
}

// BulkAction handles POST /api/bulk-action — applies an action to multiple scan IDs.
// For release and delete, messages are grouped by account so all messages for a given
// account share a single authenticated IMAP session rather than one session per message.
// Each account-group runs concurrently (bounded by imapSem).
func (h *ActionsHandler) BulkAction(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Action string `json:"action"`
		IDs    []uint `json:"ids"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10) // 8 KB — plenty for 200 IDs
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if len(req.IDs) == 0 || len(req.IDs) > 200 {
		http.Error(w, "ids must be 1–200", http.StatusBadRequest)
		return
	}
	actor := actorFromRequest(r)
	failed := 0
	var errs []string

	// imapSem limits concurrent IMAP sessions (one per account group, not per message).
	const imapConcurrency = 5
	imapSem := make(chan struct{}, imapConcurrency)
	outcomes := make(chan imapOutcome, len(req.IDs))
	var wg sync.WaitGroup

	// scansByAccount groups loaded scan rows by account name for bulk IMAP batching.
	type scanGroup struct {
		act   IMAPActions
		scans []db.Scan
	}
	accountGroups := make(map[string]*scanGroup)

	// mailboxGroups groups delete targets by (account, mailbox) pair.
	type mailboxKey struct{ account, mailbox string }
	mailboxGroups := make(map[mailboxKey]*scanGroup)

	for _, id := range req.IDs {
		var scan db.Scan
		if err := h.gdb.First(&scan, id).Error; err != nil {
			failed++
			errs = append(errs, fmt.Sprintf("id %d not found", id))
			continue
		}
		switch req.Action {
		case "release":
			act, ok := h.registry.GetActions(scan.AccountName)
			if !ok {
				failed++
				errs = append(errs, fmt.Sprintf("id %d: unknown account %q", id, scan.AccountName))
				continue
			}
			g, exists := accountGroups[scan.AccountName]
			if !exists {
				g = &scanGroup{act: act}
				accountGroups[scan.AccountName] = g
			}
			g.scans = append(g.scans, scan)

		case "delete":
			act, ok := h.registry.GetActions(scan.AccountName)
			if !ok {
				failed++
				errs = append(errs, fmt.Sprintf("id %d: unknown account %q", id, scan.AccountName))
				continue
			}
			key := mailboxKey{scan.AccountName, scan.IMAPMailbox}
			g, exists := mailboxGroups[key]
			if !exists {
				g = &scanGroup{act: act}
				mailboxGroups[key] = g
			}
			g.scans = append(g.scans, scan)

		case "learn-spam":
			if scan.EMLPath == "" {
				failed++
				errs = append(errs, fmt.Sprintf("id %d: no EML stored", id))
				continue
			}
			raw, err := h.store.Read(scan.EMLPath)
			if err != nil {
				failed++
				errs = append(errs, fmt.Sprintf("id %d: read EML: %v", id, err))
				continue
			}
			// Best-effort Rspamd training — status update proceeds even if Rspamd is down.
			if lerr := h.rspamd.LearnSpam(r.Context(), raw); lerr != nil {
				h.log.Warn("bulk learn-spam rspamd failed", "scan_id", scan.ID, "err", lerr)
			}
			if err := h.gdb.Write(func(tx *gorm.DB) error {
				return updateStatus(tx, &scan, db.StatusLearnedSpam, actor, "bulk learn spam")
			}); err != nil {
				failed++
				errs = append(errs, fmt.Sprintf("id %d: %v", id, err))
				continue
			}
			outcomes <- imapOutcome{id: scan.ID, action: "learn-spam"}

		default:
			http.Error(w, "unknown action", http.StatusBadRequest)
			return
		}
	}

	// Dispatch one goroutine per account-group for release (amortizes TLS+LOGIN).
	for _, g := range accountGroups {
		gCopy := g
		wg.Add(1)
		imapSem <- struct{}{}
		go func() { // #nosec G118 -- async bulk action outlives the HTTP request; uses its own timeout context
			defer func() { <-imapSem; wg.Done() }()
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			uids := make([]uint32, len(gCopy.scans))
			for i, s := range gCopy.scans {
				uids[i] = s.IMAPUID
			}
			if err := gCopy.act.BulkReleaseToInbox(ctx, uids); err != nil {
				h.log.Warn("bulk release IMAP failed", "account", gCopy.scans[0].AccountName, "err", err)
				for _, s := range gCopy.scans {
					outcomes <- imapOutcome{id: s.ID, action: "release", err: err}
				}
				return
			}
			for i := range gCopy.scans {
				s := gCopy.scans[i]
				h.gdb.Write(func(tx *gorm.DB) error { //nolint:errcheck
					return updateStatus(tx, &s, db.StatusReleased, actor, "bulk release")
				})
				outcomes <- imapOutcome{id: s.ID, action: "release"}
			}
		}()
	}

	// Dispatch one goroutine per account+mailbox group for delete.
	for key, g := range mailboxGroups {
		gCopy := g
		mailbox := key.mailbox
		wg.Add(1)
		imapSem <- struct{}{}
		go func() { // #nosec G118 -- async bulk action outlives the HTTP request; uses its own timeout context
			defer func() { <-imapSem; wg.Done() }()
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			uids := make([]uint32, len(gCopy.scans))
			for i, s := range gCopy.scans {
				uids[i] = s.IMAPUID
			}
			if err := gCopy.act.BulkDeleteMessages(ctx, mailbox, uids); err != nil {
				h.log.Warn("bulk delete IMAP failed", "mailbox", mailbox, "err", err)
				for _, s := range gCopy.scans {
					outcomes <- imapOutcome{id: s.ID, action: "delete", err: err}
				}
				return
			}
			for i := range gCopy.scans {
				s := gCopy.scans[i]
				h.gdb.Write(func(tx *gorm.DB) error { //nolint:errcheck
					return updateStatus(tx, &s, db.StatusDeleted, actor, "bulk delete")
				})
				outcomes <- imapOutcome{id: s.ID, action: "delete"}
			}
		}()
	}

	// Wait for all IMAP goroutines to finish before tallying results.
	wg.Wait()
	close(outcomes)

	succeeded := 0
	for o := range outcomes {
		if o.err != nil {
			failed++
			errs = append(errs, fmt.Sprintf("id %d %s: %v", o.id, o.action, o.err))
		} else {
			succeeded++
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{ // nosemgrep: go.lang.security.audit.xss.no-direct-write-to-responsewriter.no-direct-write-to-responsewriter
		"succeeded": succeeded, "failed": failed, "errors": errs,
	}) //nolint:errcheck
}

// actorFromRequest extracts the authenticated username from the request context.
func actorFromRequest(r *http.Request) string {
	if sess := auth.SessionFromContext(r); sess != nil {
		return "user:" + sess.Username
	}
	return "user:unknown"
}
