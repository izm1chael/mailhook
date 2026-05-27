package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	netmail "net/mail"
	"strings"
	"sync"
	"time"

	"github.com/izm1chael/mailhook/config"
	"github.com/izm1chael/mailhook/db"
	"github.com/izm1chael/mailhook/metrics"
	"github.com/izm1chael/mailhook/storage"
	"gorm.io/datatypes"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// stageTimeouts defines the per-scanner hard deadline.
// Each scanner's context is derived from the parent ctx (so shutdown still cancels),
// but is bounded by the stage-specific limit to prevent a slow service from
// blocking the whole pipeline.
var stageTimeouts = map[string]time.Duration{
	"rspamd":       2 * time.Second,
	"clamav":       5 * time.Second,
	"yara":         5 * time.Second,
	"urlcheck":     500 * time.Millisecond,
	"urlunshorten": 20 * time.Second,
	"nrdcheck":     15 * time.Second,
	"ipreputation":    2 * time.Second,
	"virustotal":      3 * time.Second,
	"htmlsmuggling":    500 * time.Millisecond,
	"hiddentextdetect": 500 * time.Millisecond,
	"malwarebazaar":    500 * time.Millisecond,
	"onnx":             5 * time.Second,
}

// Scanner is the interface all scan engines implement.
type Scanner interface {
	Name() string
	Scan(ctx context.Context, email *Email) ScanResult
}

// IMAPActions is the interface the pipeline uses to move/delete messages.
type IMAPActions interface {
	// MoveToQuarantine returns the new UID assigned in the quarantine folder
	// (from the COPYUID response) and the quarantine folder name so callers
	// can persist them in the scan record (F-056).
	MoveToQuarantine(ctx context.Context, mailbox string, uid uint32) (uint32, string, error)
	ReleaseToInbox(ctx context.Context, uid uint32) error
	DeleteMessage(ctx context.Context, mailbox string, uid uint32) error
	FlagMessage(ctx context.Context, mailbox string, uid uint32) error
}

// Notifier sends push notifications.
type Notifier interface {
	Send(ctx context.Context, email *Email, vd VerdictDecision)
	NotifyEngineDown(component string)
}

// SSEBroadcaster broadcasts events to connected SSE clients.
type SSEBroadcaster interface {
	Broadcast(data []byte)
}

// Pipeline orchestrates the multi-scanner fan-out, verdict, and post-processing
// for a single email message.
type Pipeline struct {
	scanners  []Scanner
	store     *storage.Store
	gdb       *db.DB
	actions   IMAPActions
	hub       SSEBroadcaster
	notifier  Notifier
	cfg       *config.Config
	log       *slog.Logger
	semaphore chan struct{} // bounds concurrent scans
}

// New creates a Pipeline. sem is the global concurrency semaphore shared across all
// pipeline instances; pass nil to create a per-instance semaphore (useful in tests).
func New(
	scanners []Scanner,
	store *storage.Store,
	gdb *db.DB,
	actions IMAPActions,
	hub SSEBroadcaster,
	notifier Notifier,
	cfg *config.Config,
	log *slog.Logger,
	sem chan struct{},
) *Pipeline {
	if sem == nil {
		max := cfg.MaxConcurrentScans
		if max <= 0 {
			max = 20
		}
		sem = make(chan struct{}, max)
	}
	return &Pipeline{
		scanners:  scanners,
		store:     store,
		gdb:       gdb,
		actions:   actions,
		hub:       hub,
		notifier:  notifier,
		cfg:       cfg,
		log:       log,
		semaphore: sem,
	}
}

// Process handles one email end-to-end. Designed to be called as a goroutine.
func (p *Pipeline) Process(ctx context.Context, accountName string, raw []byte, uid uint32, mailbox string) {
	p.process(ctx, accountName, raw, uid, mailbox, db.SourceLive)
}

// ProcessBackfill is like Process but skips all IMAP actions (no quarantine, no delete,
// no flag, no \Seen mark). The scan record is stored with source="backfill" and
// status="INBOX" so the user can review and act manually from the web UI.
func (p *Pipeline) ProcessBackfill(ctx context.Context, accountName string, raw []byte, uid uint32, mailbox string) {
	p.process(ctx, accountName, raw, uid, mailbox, db.SourceBackfill)
}

func (p *Pipeline) process(ctx context.Context, accountName string, raw []byte, uid uint32, mailbox, source string) {
	// Top-level panic recovery: Parse() runs attacker-controlled bytes through
	// image.Decode, gozxing QR, and goquery — any of which can panic on a crafted
	// message. Without this, a single malicious email crashes the daemon.
	isBackfill := source == db.SourceBackfill

	defer func() {
		if r := recover(); r != nil {
			p.log.Error("pipeline process panic recovered — quarantining message",
				"uid", uid, "account", accountName, "panic", r)
			metrics.ScansTotal.WithLabelValues(db.VerdictSuspicious).Inc()
			now := time.Now()
			status := db.StatusQuarantined
			if isBackfill {
				status = db.StatusInbox
			}
			rec := &db.Scan{
				AccountName:   accountName,
				AccountUID:    db.MakeAccountUID(accountName, mailbox, uid),
				IMAPMailbox:   mailbox,
				IMAPUID:       uid,
				Verdict:       db.VerdictSuspicious,
				VerdictReason: fmt.Sprintf("process panic: %v", r),
				Confidence:    1.0,
				Status:        status,
				Source:        source,
				ActionedBy:    "auto",
				CreatedAt:     now,
				ActionedAt:    &now,
			}
			if err := p.gdb.Write(func(tx *gorm.DB) error { return tx.Create(rec).Error }); err != nil {
				p.log.Error("panic recovery: scan record create failed", "err", err)
				return
			}
			if isBackfill {
				return
			}
			// Use a fresh context: the original ctx may be expired after a panic.
			imapCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			qUID, qMailbox, imapErr := p.takeIMAPAction(imapCtx, "quarantine", mailbox, uid)
			if imapErr != nil {
				p.log.Error("panic recovery: imap quarantine failed — message left in inbox",
					"uid", uid, "account", accountName, "err", imapErr)
				p.gdb.Write(func(tx *gorm.DB) error { //nolint:errcheck
					tx.Model(rec).Update("status", db.StatusInbox)
					tx.Create(&db.AuditLog{ScanID: rec.ID, Action: "IMAP_FAIL", Actor: "auto",
						Note: fmt.Sprintf("panic-recovery quarantine failed: %v", imapErr)})
					return nil
				})
			} else {
				p.auditQuarantineDesync(rec, p.log, p.updateQuarantineUID(rec, accountName, qUID, qMailbox))
			}
		}
	}()

	// Acquire a concurrency slot; blocks if the pipeline is at capacity.
	// Goroutine stack is ~8KB while waiting vs MB when scanners are running.
	select {
	case p.semaphore <- struct{}{}:
	case <-ctx.Done():
		p.log.Warn("pipeline slot wait cancelled", "uid", uid, "account", accountName)
		return
	}
	defer func() { <-p.semaphore }()

	start := time.Now()

	// Scoped logger carries identity fields for every log line in this email's lifecycle.
	log := p.log.With("account", accountName, "uid", uid, "mailbox", mailbox)

	email, err := Parse(raw, accountName, uid, mailbox, int64(p.cfg.MaxEmailSizeMB)*1024*1024, p.cfg.TrustedAuthservID)
	if err != nil {
		log.Error("email parse failed — quarantining unparseable message", "err", err)
		metrics.ScansTotal.WithLabelValues(db.VerdictSuspicious).Inc()
		now := time.Now()
		parseStatus := db.StatusQuarantined
		if isBackfill {
			parseStatus = db.StatusInbox
		}
		rec := &db.Scan{
			AccountName:   accountName,
			AccountUID:    db.MakeAccountUID(accountName, mailbox, uid),
			IMAPMailbox:   mailbox,
			IMAPUID:       uid,
			Verdict:       db.VerdictSuspicious,
			VerdictReason: fmt.Sprintf("unparseable message: %v", err),
			Confidence:    1.0,
			Status:        parseStatus,
			Source:        source,
			ActionedBy:    "auto",
			CreatedAt:     now,
			ActionedAt:    &now,
		}
		if dbErr := p.gdb.Write(func(tx *gorm.DB) error { return tx.Create(rec).Error }); dbErr != nil {
			log.Error("parse-failure scan record create failed", "err", dbErr)
			return
		}
		if isBackfill {
			return
		}
		qUID, qMailbox, imapErr := p.takeIMAPAction(ctx, "quarantine", mailbox, uid)
		if imapErr != nil {
			log.Error("parse-failure imap quarantine failed", "err", imapErr)
			p.gdb.Write(func(tx *gorm.DB) error { //nolint:errcheck
				tx.Model(rec).Update("status", db.StatusInbox)
				tx.Create(&db.AuditLog{ScanID: rec.ID, Action: "IMAP_FAIL", Actor: "auto",
					Note: fmt.Sprintf("parse-failure quarantine failed: %v", imapErr)})
				return nil
			})
		} else {
			p.auditQuarantineDesync(rec, log, p.updateQuarantineUID(rec, accountName, qUID, qMailbox))
		}
		return
	}
	log = log.With("msg_id", email.MessageID)

	// Blocklist check — evaluated first so a blocklisted sender cannot be released
	// by a whitelist entry. Immediate quarantine without scanning.
	if bl := p.matchBlocklist(email); bl != nil {
		vd := decided("quarantine", "SPAM", "blocklisted: "+bl.Entry, 1.0, nil)
		emlPath, _ := p.store.Write(accountName, email.MessageID, email.IMAPUID, raw)
		rec := p.buildScanRecord(email, vd, emlPath)
		rec.Source = source
		if isBackfill {
			rec.Status = db.StatusInbox
		}
		if err := p.gdb.Write(func(tx *gorm.DB) error { return tx.Create(rec).Error }); err != nil {
			log.Error("blocklist scan record create failed — skipping IMAP action", "err", err)
			return
		}
		if !isBackfill {
			qUID, qMailbox, imapErr := p.takeIMAPAction(ctx, "quarantine", mailbox, uid)
			if imapErr != nil {
				log.Error("imap action failed after retries — reverting scan status", "decision", "quarantine", "err", imapErr)
				p.gdb.Write(func(tx *gorm.DB) error { //nolint:errcheck
					tx.Model(rec).Update("status", db.StatusInbox)
					tx.Create(&db.AuditLog{
						ScanID: rec.ID,
						Action: "IMAP_FAIL",
						Actor:  "auto",
						Note:   fmt.Sprintf("imap quarantine failed: %v", imapErr),
					})
					return nil
				})
			} else {
				p.updateQuarantineUID(rec, email.AccountName, qUID, qMailbox)
			}
		}
		metrics.ScansTotal.WithLabelValues("SPAM").Inc()
		metrics.PipelineDuration.Observe(time.Since(start).Seconds())
		p.incrementDailyStat("SPAM")
		log.Info("blocklisted", "entry", maskEntry(bl.Entry))
		return
	}

	// Whitelist check — evaluated after blocklist so a blocklisted sender cannot escape
	// via a whitelist bypass. bypass_scan is only honoured when SPF/DKIM/DMARC alignment
	// passes; otherwise fall through to normal scanning to prevent spoofed-From bypass.
	if wl := p.matchWhitelist(email); wl != nil {
		if wl.BypassScan && senderAuthAligned(email) {
			vd := decided("pass", "CLEAN", "whitelisted (bypass): "+wl.Entry, 1.0, nil)
			emlPath, _ := p.store.Write(accountName, email.MessageID, email.IMAPUID, raw)
			if !p.cfg.EMLCleanRetain && emlPath != "" {
				p.store.Delete(emlPath) //nolint:errcheck
				emlPath = ""
			}
			rec := p.buildScanRecord(email, vd, emlPath)
			p.gdb.Write(func(tx *gorm.DB) error { return tx.Create(rec).Error }) //nolint:errcheck
			metrics.ScansTotal.WithLabelValues("CLEAN").Inc()
			metrics.PipelineDuration.Observe(time.Since(start).Seconds())
			p.incrementDailyStat("CLEAN")
			log.Info("whitelisted (bypass)", "entry", maskEntry(wl.Entry))
			return
		}
		if wl.BypassScan && !senderAuthAligned(email) {
			log.Warn("whitelist bypass_scan ignored — SPF/DKIM/DMARC alignment failed; scanning anyway",
				"entry", maskEntry(wl.Entry),
				"spf", email.SPFResult, "dkim", email.DKIMResult, "dmarc", email.DMARCResult)
		}
		// bypass_scan=false or auth failed: fall through to scanning, but force INBOX at the end
		email.WhitelistEntry = wl.Entry
	}

	// Persist EML before scanning so we have it even if the scan panics
	emlPath, err := p.store.Write(accountName, email.MessageID, email.IMAPUID, raw)
	if err != nil {
		log.Warn("eml store failed", "err", err)
	}

	// Fan-out: run all scanners concurrently, each under its own stage timeout.
	// The stage ctx is derived from the parent so shutdown cancels all scanners.
	resultCh := make(chan ScanResult, len(p.scanners))
	var wg sync.WaitGroup
	for _, s := range p.scanners {
		wg.Add(1)
		go func(s Scanner) {
			defer wg.Done()
			defer func() {
				if rec := recover(); rec != nil {
					p.log.Error("scanner panic recovered", "scanner", s.Name(), "panic", rec)
					metrics.ScannerErrors.WithLabelValues(s.Name()).Inc()
					metrics.ScannerUp.WithLabelValues(s.Name()).Set(0)
					resultCh <- ScanResult{Scanner: s.Name(), Verdict: "error", Detail: "panic recovered"}
				}
			}()
			timeout := stageTimeouts[s.Name()]
			if timeout == 0 {
				timeout = p.cfg.ScanTimeout
			}
			sCtx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			t0 := time.Now()
			r := s.Scan(sCtx, email)
			metrics.ScannerDuration.WithLabelValues(s.Name(), r.Verdict).Observe(time.Since(t0).Seconds())
			if r.Verdict == "error" {
				metrics.ScannerErrors.WithLabelValues(s.Name()).Inc()
				metrics.ScannerUp.WithLabelValues(s.Name()).Set(0)
				if p.notifier != nil {
					p.notifier.NotifyEngineDown(s.Name())
				}
			} else {
				metrics.ScannerUp.WithLabelValues(s.Name()).Set(1)
			}
			resultCh <- r
		}(s)
	}
	wg.Wait()
	close(resultCh)

	var results []ScanResult
	for r := range resultCh {
		results = append(results, r)
	}

	thresholds := Thresholds{
		SpamScore:   p.cfg.GetSpamScore(),
		RejectScore: p.cfg.GetRejectScore(),
	}
	vd := Decide(thresholds, email, results)

	// Whitelist scan-then-release override: scanner ran, but force INBOX
	if email.WhitelistEntry != "" {
		vd.Decision = "pass"
		vd.Reason = "whitelisted (scan-and-release): " + maskEntry(email.WhitelistEntry)
	}

	// EML clean-retain: delete EML for CLEAN mail if not configured to keep it
	if !p.cfg.EMLCleanRetain && vd.Verdict == db.VerdictClean && emlPath != "" {
		if err := p.store.Delete(emlPath); err == nil {
			emlPath = ""
		}
	}

	// Persist scan record — upsert so rescan updates the existing row.
	// The idx_account_uid unique index means a plain Create would fail on rescan.
	scanRecord := p.buildScanRecord(email, vd, emlPath)
	scanRecord.Source = source
	if isBackfill {
		// Backfill: record the threat verdict but leave the message in place.
		scanRecord.Status = db.StatusInbox
	}
	if err := p.gdb.Write(func(tx *gorm.DB) error {
		return tx.Clauses(clause.OnConflict{
			Columns: []clause.Column{{Name: "account_uid"}, {Name: "imap_uid"}},
			DoUpdates: clause.AssignmentColumns([]string{
				"verdict", "verdict_reason", "confidence",
				"rspamd_score", "rspamd_action", "rspamd_symbols",
				"spf_result", "dkim_result", "dmarc_result",
				"clam_av_status", "url_hits", "resolved_url_hits", "nrd_hits",
				"status", "eml_path", "updated_at",
			}),
		}).Create(scanRecord).Error
	}); err != nil {
		log.Error("scan record upsert failed — skipping IMAP action", "err", err)
		return
	}

	if !isBackfill {
		// Take IMAP action; revert DB status if action fails after retries.
		// On successful quarantine, persist the new UID assigned in the destination
		// folder (F-056) so Release/Delete operate on the correct UID.
		qUID, qMailbox, imapErr := p.takeIMAPAction(ctx, vd.Decision, mailbox, uid)
		if imapErr != nil {
			log.Error("imap action failed after retries — reverting scan status",
				"decision", vd.Decision, "err", imapErr)
			p.gdb.Write(func(tx *gorm.DB) error { //nolint:errcheck
				tx.Model(scanRecord).Update("status", db.StatusInbox)
				tx.Create(&db.AuditLog{
					ScanID: scanRecord.ID,
					Action: "IMAP_FAIL",
					Actor:  "auto",
					Note:   fmt.Sprintf("imap %s failed: %v", vd.Decision, imapErr),
				})
				return nil
			})
		} else if vd.Decision == "quarantine" {
			p.auditQuarantineDesync(scanRecord, log, p.updateQuarantineUID(scanRecord, email.AccountName, qUID, qMailbox))
		}
	}

	// Notifications (fire-and-forget)
	if p.notifier != nil {
		if isBackfill {
			if vd.Verdict != db.VerdictClean {
				backfillVD := vd
				backfillVD.Reason = "[Historical scan] " + vd.Reason
				p.notifier.Send(ctx, email, backfillVD)
			}
		} else if vd.Decision != "pass" {
			p.notifier.Send(ctx, email, vd)
		}
	}

	// SSE broadcast for live dashboard updates
	if p.hub != nil {
		if data, err := json.Marshal(scanRecord); err == nil {
			p.hub.Broadcast(data)
		}
	}

	// Audit log
	action := verdictToAction(vd)
	if isBackfill {
		action = db.ActionBackfill
	}
	if err := p.gdb.Write(func(tx *gorm.DB) error {
		return tx.Create(&db.AuditLog{
			ScanID:    scanRecord.ID,
			Action:    action,
			Actor:     "auto",
			Note:      vd.Reason,
			CreatedAt: time.Now(),
		}).Error
	}); err != nil {
		log.Error("audit log write failed", "scan_id", scanRecord.ID, "err", err)
	}

	// Metrics (spec §17 names)
	metrics.ScansTotal.WithLabelValues(vd.Verdict).Inc()
	metrics.PipelineDuration.Observe(time.Since(start).Seconds())

	// Daily stat aggregation
	p.incrementDailyStat(vd.Verdict)

	log.Info("processed",
		"verdict", vd.Verdict,
		"decision", vd.Decision,
		"reason", util_truncate(vd.Reason, 100),
		"elapsed_ms", time.Since(start).Milliseconds(),
	)
}

// takeIMAPAction executes the IMAP side-effect for the given verdict decision.
// For quarantine actions it returns the new UID in the destination folder and
// the destination folder name so callers can update the scan record (F-056).
// Returns (0, "", nil) for non-quarantine decisions.
func (p *Pipeline) takeIMAPAction(ctx context.Context, decision, mailbox string, uid uint32) (quarantineUID uint32, quarantineMailbox string, err error) {
	delays := []time.Duration{0, time.Second, 2 * time.Second, 4 * time.Second}

	switch decision {
	case "delete":
		for _, d := range delays {
			if d > 0 {
				select {
				case <-ctx.Done():
					return 0, "", ctx.Err()
				case <-time.After(d):
				}
			}
			if err = p.actions.DeleteMessage(ctx, mailbox, uid); err == nil {
				return 0, "", nil
			}
			p.log.Warn("imap action attempt failed", "decision", decision, "uid", uid, "err", err)
		}
		return 0, "", err

	case "quarantine":
		var qUID uint32
		var qMailbox string
		for _, d := range delays {
			if d > 0 {
				select {
				case <-ctx.Done():
					return 0, "", ctx.Err()
				case <-time.After(d):
				}
			}
			qUID, qMailbox, err = p.actions.MoveToQuarantine(ctx, mailbox, uid)
			if err == nil {
				return qUID, qMailbox, nil
			}
			p.log.Warn("imap action attempt failed", "decision", decision, "uid", uid, "err", err)
		}
		return 0, "", err

	case "flag":
		for _, d := range delays {
			if d > 0 {
				select {
				case <-ctx.Done():
					return 0, "", ctx.Err()
				case <-time.After(d):
				}
			}
			if err = p.actions.FlagMessage(ctx, mailbox, uid); err == nil {
				return 0, "", nil
			}
			p.log.Warn("imap action attempt failed", "decision", decision, "uid", uid, "err", err)
		}
		return 0, "", err

	default:
		return 0, "", nil
	}
}

// updateQuarantineUID persists the new IMAP UID and mailbox assigned after a
// successful quarantine MOVE. The server assigns a new UID in the destination
// folder; without this update Release/Delete would address a non-existent UID
// (F-056). When newUID is 0 (server emitted malformed COPYUID), only the mailbox
// column is updated so operators can at least see the correct folder.
func (p *Pipeline) updateQuarantineUID(scanRecord *db.Scan, accountName string, newUID uint32, newMailbox string) error {
	if newMailbox == "" {
		return nil
	}
	return p.gdb.Write(func(tx *gorm.DB) error {
		updates := map[string]any{"imap_mailbox": newMailbox}
		if newUID > 0 {
			updates["imap_uid"] = newUID
			updates["account_uid"] = db.MakeAccountUID(accountName, newMailbox, newUID)
		}
		return tx.Model(scanRecord).Updates(updates).Error
	})
}

// auditQuarantineDesync logs and records a failed quarantine-UID persist so the
// DB/IMAP divergence is never silent (F-056). The message is genuinely in the
// quarantine folder, so we do not revert status — we surface the inconsistency
// for operator reconciliation, mirroring the IMAP_FAIL audit pattern.
func (p *Pipeline) auditQuarantineDesync(scanRecord *db.Scan, log *slog.Logger, err error) {
	if err == nil {
		return
	}
	log.Error("quarantine UID persist failed — release/delete will target stale UID",
		"scan_id", scanRecord.ID, "err", err)
	p.gdb.Write(func(tx *gorm.DB) error { //nolint:errcheck
		return tx.Create(&db.AuditLog{
			ScanID: scanRecord.ID,
			Action: "QUAR_DESYNC",
			Actor:  "auto",
			Note:   fmt.Sprintf("quarantine UID persist failed: %v", err),
		}).Error
	})
}

// matchWhitelist returns the first Whitelist entry that matches the email's
// sender address or sender domain. Uses a single IN query instead of sequential
// per-candidate lookups to reduce DB round-trips on the hot path (F-009).
func (p *Pipeline) matchWhitelist(email *Email) *db.Whitelist {
	candidates := listCandidates(email)
	var entries []db.Whitelist
	if err := p.gdb.Where("entry IN ?", candidates).Find(&entries).Error; err != nil || len(entries) == 0 {
		return nil
	}
	// Prefer the most-specific match (full address over @domain).
	for _, want := range candidates {
		for i := range entries {
			if entries[i].Entry == want {
				return &entries[i]
			}
		}
	}
	return &entries[0]
}

// matchBlocklist returns the first Blocklist entry that matches the email.
// Uses a single IN query instead of sequential per-candidate lookups (F-009).
func (p *Pipeline) matchBlocklist(email *Email) *db.Blocklist {
	candidates := listCandidates(email)
	var entries []db.Blocklist
	if err := p.gdb.Where("entry IN ?", candidates).Find(&entries).Error; err != nil || len(entries) == 0 {
		return nil
	}
	for _, want := range candidates {
		for i := range entries {
			if entries[i].Entry == want {
				return &entries[i]
			}
		}
	}
	return &entries[0]
}

// listCandidates returns the values to check against allow/block lists:
// the full sender address and the @domain prefix (spec §4 EntryType).
// senderAuthAligned returns true when at least one of SPF, DKIM, or DMARC passes.
// Used to gate whitelist bypass_scan: a passing auth result means the From address
// is not trivially spoofable. Requires SPF pass AND (DKIM pass OR DMARC pass) for
// maximum confidence.
func senderAuthAligned(email *Email) bool {
	return email.SPFResult == "pass" &&
		(email.DKIMResult == "pass" || email.DMARCResult == "pass")
}

func listCandidates(email *Email) []string {
	bare := email.From
	if addr, err := netmail.ParseAddress(email.From); err == nil {
		bare = addr.Address
	}
	bare = strings.ToLower(strings.TrimSpace(bare))
	candidates := []string{bare}
	if idx := strings.LastIndex(bare, "@"); idx >= 0 {
		candidates = append(candidates, bare[idx:])
	}
	return candidates
}

// incrementDailyStat upserts today's DailyStat row for the given verdict.
// INSERT OR IGNORE + UPDATE is a single atomic operation under SQLite, avoiding
// the read-then-write race of FirstOrCreate at midnight.
func (p *Pipeline) incrementDailyStat(verdict string) {
	col := verdictToStatCol(verdict)
	if col == "" {
		return
	}
	date := time.Now().Format("2006-01-02")
	p.gdb.Write(func(tx *gorm.DB) error { //nolint:errcheck
		tx.Exec("INSERT OR IGNORE INTO daily_stats (date, clean, spam, phish, malware, suspicious, total) VALUES (?, 0, 0, 0, 0, 0, 0)", date)
		tx.Exec("UPDATE daily_stats SET "+col+" = "+col+" + 1, total = total + 1 WHERE date = ?", date)
		return nil
	})
}

func verdictToStatCol(verdict string) string {
	switch verdict {
	case "CLEAN":
		return "clean"
	case "SPAM":
		return "spam"
	case "PHISH":
		return "phish"
	case "MALWARE":
		return "malware"
	case "SUSPICIOUS":
		return "suspicious"
	}
	return ""
}

func (p *Pipeline) buildScanRecord(email *Email, vd VerdictDecision, emlPath string) *db.Scan {
	accountUID := db.MakeAccountUID(email.AccountName, email.IMAPMailbox, email.IMAPUID)

	s := &db.Scan{
		AccountName:  email.AccountName,
		AccountUID:   accountUID,
		IMAPMailbox:  email.IMAPMailbox,
		IMAPUID:      email.IMAPUID,
		MessageID:    email.MessageID,
		Subject:      email.Subject,
		From:         email.From,
		To:           email.To,
		Date:         email.Date,
		SizeBytes:    email.SizeBytes,
		EMLPath:      emlPath,
		SPFResult:    email.SPFResult,
		DKIMResult:   email.DKIMResult,
		DMARCResult:  email.DMARCResult,
		AttachmentCount: len(email.Attachments),
		Verdict:      vd.Verdict,
		VerdictReason: vd.Reason,
		Confidence:   vd.Confidence,
		ActionedBy:   "auto",
		CreatedAt:    time.Now(),
	}

	if len(email.SenderIPs) > 0 {
		s.SendingIP = email.SenderIPs[0].String()
	}
	if email.HadMIMEErrors && s.VerdictReason != "" {
		s.VerdictReason += "; MIME parse incomplete (some parts skipped)"
	} else if email.HadMIMEErrors {
		s.VerdictReason = "MIME parse incomplete (some parts skipped)"
	}

	// Map scan results back to the flat columns (and structured JSON columns).
	// vtBySHA and mbBySHA map sha256 → result for enriching attachment info below.
	vtBySHA := make(map[string]db.VTResult)
	mbBySHA := make(map[string]db.MBResult)
	for _, r := range vd.Results {
		switch r.Scanner {
		case "rspamd":
			s.RspamdScore = r.Score
			s.RspamdAction = r.Detail
			if len(r.Matches) > 0 {
				s.RspamdSymbols = datatypes.JSON(r.Matches)
			}
		case "clamav":
			if r.Verdict == "malicious" {
				s.ClamAVStatus = r.Detail
			} else if r.Verdict == "error" {
				s.ClamAVStatus = "ERROR"
			} else if r.Verdict == "skip" {
				s.ClamAVStatus = "UNAVAILABLE"
			} else {
				s.ClamAVStatus = "CLEAN"
			}
		case "yara":
			if len(r.Matches) > 0 {
				s.YARAMatches = datatypes.JSON(r.Matches)
			}
		case "urlcheck":
			if len(r.Matches) > 0 {
				s.URLHits = datatypes.JSON(r.Matches)
			}
		case "urlunshorten":
			if len(r.Matches) > 0 {
				s.ResolvedURLHits = datatypes.JSON(r.Matches)
			}
		case "nrdcheck":
			if len(r.Matches) > 0 {
				s.NRDHits = datatypes.JSON(r.Matches)
			}
		case "htmlsmuggling":
			if len(r.Matches) > 0 {
				s.HTMLSmugglingHits = datatypes.JSON(r.Matches)
			}
		case "hiddentextdetect":
			if len(r.Matches) > 0 {
				s.HiddenTextHits = datatypes.JSON(r.Matches)
			}
		case "ipreputation":
			if len(r.Matches) > 0 {
				s.IPReputation = datatypes.JSON(r.Matches)
			}
		case "virustotal":
			if len(r.Matches) > 0 {
				s.VTResults = datatypes.JSON(r.Matches)
				var vtList []db.VTResult
				if err := json.Unmarshal(r.Matches, &vtList); err == nil {
					for _, vt := range vtList {
						vtBySHA[vt.SHA256] = vt
					}
				}
			}
		case "malwarebazaar":
			if len(r.Matches) > 0 {
				s.MBResults = datatypes.JSON(r.Matches)
				var mbList []db.MBResult
				if err := json.Unmarshal(r.Matches, &mbList); err == nil {
					for _, mb := range mbList {
						mbBySHA[mb.SHA256] = mb
					}
				}
			}
		}
	}

	// Set IMAP status based on decision
	switch vd.Decision {
	case "delete":
		s.Status = db.StatusDeleted
	case "quarantine":
		s.Status = db.StatusQuarantined
	default:
		s.Status = db.StatusInbox
	}

	now := time.Now()
	s.ActionedAt = &now

	// Attachment info — enrich with VT results keyed by sha256
	if len(email.Attachments) > 0 {
		attInfos := make([]db.AttachmentInfo, len(email.Attachments))
		for i, a := range email.Attachments {
			ai := db.AttachmentInfo{
				Filename:    a.Filename,
				ContentType: a.ContentType,
				SizeBytes:   a.SizeBytes,
				SHA256:      a.SHA256,
				Extension:   a.Extension,
				IsDangerous: a.IsDangerous,
			}
			if vt, ok := vtBySHA[a.SHA256]; ok {
				ai.VTPositives = vt.Positives
				ai.VTTotal = vt.Total
			}
			if mb, ok := mbBySHA[a.SHA256]; ok {
				ai.MBSignature = mb.Signature
			}
			attInfos[i] = ai
		}
		if data, err := marshalJSON(attInfos); err == nil {
			s.Attachments = data
		}
	}

	if len(email.URLs) > 0 {
		if data, err := json.Marshal(email.URLs); err == nil {
			s.ScannedURLs = datatypes.JSON(data)
		}
	}

	return s
}

// RunScan executes the scanner fan-out and verdict engine on raw EML bytes
// without any IMAP, storage, or database side effects.
// Intended for the /api/scan bench endpoint and integration testing.
func RunScan(ctx context.Context, sc []Scanner, cfg *config.Config, raw []byte) (VerdictDecision, []ScanResult, time.Duration, error) {
	start := time.Now()
	limit := int64(cfg.MaxEmailSizeMB) * 1024 * 1024
	if limit == 0 {
		limit = 100 * 1024 * 1024
	}
	email, err := Parse(raw, "scan", 0, "INBOX", limit, cfg.TrustedAuthservID)
	if err != nil {
		return VerdictDecision{}, nil, 0, err
	}
	resultCh := make(chan ScanResult, len(sc))
	var wg sync.WaitGroup
	for _, s := range sc {
		wg.Add(1)
		go func(s Scanner) {
			defer wg.Done()
			timeout := stageTimeouts[s.Name()]
			if timeout == 0 {
				timeout = cfg.ScanTimeout
			}
			sCtx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			resultCh <- s.Scan(sCtx, email)
		}(s)
	}
	wg.Wait()
	close(resultCh)
	var results []ScanResult
	for r := range resultCh {
		results = append(results, r)
	}
	th := Thresholds{SpamScore: cfg.GetSpamScore(), RejectScore: cfg.GetRejectScore()}
	return Decide(th, email, results), results, time.Since(start), nil
}

func verdictToAction(vd VerdictDecision) string {
	switch vd.Decision {
	case "delete":
		return db.ActionDelete
	case "quarantine":
		return db.ActionQuarantine
	default:
		return "PASS"
	}
}

func marshalJSON(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}

func util_truncate(s string, max int) string {
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	return string(runes[:max]) + "…"
}

// maskEntry masks the local part of an email address or domain entry for logging.
// "alice@example.com" → "al***@example.com"; short local parts are fully masked.
func maskEntry(entry string) string {
	idx := strings.Index(entry, "@")
	if idx <= 0 {
		return entry
	}
	user := entry[:idx]
	if len(user) <= 2 {
		return strings.Repeat("*", len(user)) + entry[idx:]
	}
	return user[:2] + strings.Repeat("*", len(user)-2) + entry[idx:]
}
