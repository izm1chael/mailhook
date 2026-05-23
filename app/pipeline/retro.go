package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"time"

	imaplib "github.com/izm1chael/mailhook/imap"
	"github.com/izm1chael/mailhook/config"
	"github.com/izm1chael/mailhook/db"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// retroFeedLookup is the subset of feeds.Manager the retro scanner needs.
type retroFeedLookup interface {
	LookupURL(rawURL string) (feed, threatType string, ok bool)
	LookupURLExact(rawURL string) (feed, threatType string, ok bool)
}

// RetroNotifier is the subset of the notifier the retro scanner needs.
type RetroNotifier interface {
	NotifyRetroClawback(ctx context.Context, scan *db.Scan, hits []db.URLHit)
}

// RetroScanner re-evaluates CLEAN INBOX emails from the past N hours against
// the live in-memory threat feed index and claws them back when new hits are found.
type RetroScanner struct {
	gdb      *db.DB
	feeds    retroFeedLookup
	notifier RetroNotifier
	hub      SSEBroadcaster
	cfg      *config.Config
	log      *slog.Logger

	lookbackHours   int
	intervalMinutes int

	mu      sync.Mutex
	running bool
}

// NewRetroScanner creates a RetroScanner with a 72h lookback and 30-minute sweep interval.
func NewRetroScanner(
	gdb *db.DB,
	feeds retroFeedLookup,
	notifier RetroNotifier,
	hub SSEBroadcaster,
	cfg *config.Config,
	log *slog.Logger,
) *RetroScanner {
	return &RetroScanner{
		gdb:             gdb,
		feeds:           feeds,
		notifier:        notifier,
		hub:             hub,
		cfg:             cfg,
		log:             log,
		lookbackHours:   72,
		intervalMinutes: 30,
	}
}

// Run blocks until ctx is cancelled. Designed to be called as a goroutine.
func (r *RetroScanner) Run(ctx context.Context) {
	r.log.Info("retro scanner started",
		"lookback_hours", r.lookbackHours,
		"interval_minutes", r.intervalMinutes,
	)
	r.sweep(ctx)

	ticker := time.NewTicker(time.Duration(r.intervalMinutes) * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			r.sweep(ctx)
		case <-ctx.Done():
			r.log.Info("retro scanner stopped")
			return
		}
	}
}

func (r *RetroScanner) sweep(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	r.mu.Lock()
	if r.running {
		r.mu.Unlock()
		return
	}
	r.running = true
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		r.running = false
		r.mu.Unlock()
	}()

	cutoff := time.Now().Add(-time.Duration(r.lookbackHours) * time.Hour)

	// Page through candidates to avoid materializing the full 72h result set (F-031).
	const batchSize = 200
	var lastID uint
	r.log.Debug("retro sweep: starting paginated scan")
	for {
		if ctx.Err() != nil {
			return
		}
		var candidates []db.Scan
		if err := r.gdb.DB.
			Where("id > ? AND verdict = ? AND status = ? AND created_at > ? AND scanned_urls IS NOT NULL AND scanned_urls != 'null'",
				lastID, db.VerdictClean, db.StatusInbox, cutoff).
			Order("id asc").
			Limit(batchSize).
			Find(&candidates).Error; err != nil {
			r.log.Error("retro sweep query failed", "err", err)
			return
		}
		if len(candidates) == 0 {
			break
		}
		r.log.Debug("retro sweep batch", "count", len(candidates))
		for i := range candidates {
			if ctx.Err() != nil {
				return
			}
			r.evaluate(ctx, &candidates[i])
		}
		lastID = candidates[len(candidates)-1].ID
		if len(candidates) < batchSize {
			break
		}
	}
}

func (r *RetroScanner) evaluate(ctx context.Context, scan *db.Scan) {
	var urls []string
	if err := json.Unmarshal([]byte(scan.ScannedURLs), &urls); err != nil || len(urls) == 0 {
		return
	}

	var hits []db.URLHit
	for _, u := range urls {
		// Apply the same shared-hosting guard as the live urlcheck scanner (F-030):
		// for platforms where many paths coexist, only flag on exact URL match.
		domain := retroExtractDomain(u)
		var feed, threatType string
		var ok bool
		if retroIsSharedHostingDomain(domain) {
			feed, threatType, ok = r.feeds.LookupURLExact(u)
		} else {
			feed, threatType, ok = r.feeds.LookupURL(u)
		}
		if ok {
			hits = append(hits, db.URLHit{
				URL:        u,
				Feed:       feed,
				ThreatType: threatType,
			})
		}
	}

	if len(hits) == 0 {
		return
	}

	r.log.Warn("retro: threat found in previously-clean email",
		"scan_id", scan.ID,
		"account", scan.AccountName,
		"from", scan.From,
		"url", hits[0].URL,
		"feed", hits[0].Feed,
	)
	r.clawback(ctx, scan, hits)
}

func (r *RetroScanner) clawback(ctx context.Context, scan *db.Scan, hits []db.URLHit) {
	var account db.Account
	if err := r.gdb.DB.Where("name = ?", scan.AccountName).First(&account).Error; err != nil {
		r.log.Error("retro clawback: account not found",
			"account", scan.AccountName, "scan_id", scan.ID, "err", err)
		return
	}

	accCfg := config.AccountConfig{
		Name:          account.Name,
		Host:          account.Host,
		Port:          account.Port,
		User:          account.User,
		Pass:          string(account.Pass),
		Quarantine:    account.Quarantine,
		Mailbox:       account.Mailbox,
		TLSSkipVerify: account.TLSSkipVerify,
	}
	if accCfg.Port == 0 {
		accCfg.Port = 993
	}
	if accCfg.Quarantine == "" {
		accCfg.Quarantine = "Quarantine"
	}

	actions := imaplib.NewActions(accCfg, r.log)
	qUID, qMailbox, moveErr := actions.MoveToQuarantine(ctx, scan.IMAPMailbox, scan.IMAPUID)
	if moveErr != nil {
		r.log.Error("retro clawback: IMAP move failed",
			"scan_id", scan.ID, "uid", scan.IMAPUID,
			"mailbox", scan.IMAPMailbox, "err", moveErr)
		return
	}

	verdict := db.VerdictPhish
	for _, h := range hits {
		if h.ThreatType == "malware" {
			verdict = db.VerdictMalware
			break
		}
	}

	hitsJSON, _ := json.Marshal(hits)
	reason := fmt.Sprintf("retrospective: %s now in %s (%s)",
		hits[0].URL, hits[0].Feed, hits[0].ThreatType)
	now := time.Now()

	if err := r.gdb.Write(func(tx *gorm.DB) error {
		updates := map[string]interface{}{
			"verdict":        verdict,
			"verdict_reason": reason,
			"status":         db.StatusQuarantined,
			"url_hits":       datatypes.JSON(hitsJSON),
			"actioned_by":    "retro",
			"actioned_at":    &now,
			"imap_mailbox":   qMailbox,
		}
		if qUID > 0 {
			updates["imap_uid"] = qUID
			updates["account_uid"] = db.MakeAccountUID(scan.AccountName, qMailbox, qUID)
		}
		if err := tx.Model(scan).
			Where("status = ?", db.StatusInbox).
			Updates(updates).Error; err != nil {
			return err
		}
		return tx.Create(&db.AuditLog{
			ScanID:    scan.ID,
			Action:    db.ActionRetroQuarantine,
			Actor:     "auto",
			Note:      reason,
			CreatedAt: now,
		}).Error
	}); err != nil {
		r.log.Error("retro clawback: quarantine UID persist failed — release/delete will target stale UID",
			"scan_id", scan.ID, "err", err)
	}

	if r.notifier != nil {
		r.notifier.NotifyRetroClawback(ctx, scan, hits)
	}

	if r.hub != nil {
		var updated db.Scan
		if err := r.gdb.DB.First(&updated, scan.ID).Error; err == nil {
			if data, err := json.Marshal(&updated); err == nil {
				r.hub.Broadcast(data)
			}
		}
	}

	r.log.Info("retro clawback complete",
		"scan_id", scan.ID, "verdict", verdict,
		"feed", hits[0].Feed, "url", hits[0].URL,
	)
}

// retroExtractDomain extracts the lowercased host from rawURL, stripping www. prefix.
func retroExtractDomain(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	host := strings.ToLower(u.Hostname())
	return strings.TrimPrefix(host, "www.")
}

// retroIsSharedHostingDomain mirrors the urlcheck scanner's isSharedHostingDomain guard.
// These platforms host many tenants so a host-level match would cause false-positive clawbacks.
var retroSharedHostingDomains = map[string]struct{}{
	"github.com": {}, "githubusercontent.com": {}, "github.io": {},
	"gitlab.com": {}, "bitbucket.org": {},
	"drive.google.com": {}, "docs.google.com": {}, "storage.googleapis.com": {},
	"sharepoint.com": {}, "onedrive.live.com": {}, "1drv.ms": {},
	"dropbox.com": {}, "box.com": {},
	"s3.amazonaws.com": {}, "s3-us-west-2.amazonaws.com": {},
	"blob.core.windows.net": {}, "cloudfront.net": {},
	"pages.dev": {}, "workers.dev": {},
	"netlify.app": {}, "vercel.app": {}, "herokuapp.com": {},
	"azurewebsites.net": {}, "web.app": {}, "firebaseapp.com": {},
	"wordpress.com": {}, "blogspot.com": {}, "tumblr.com": {},
	"medium.com": {}, "substack.com": {}, "wixsite.com": {},
}

func retroIsSharedHostingDomain(host string) bool {
	if _, ok := retroSharedHostingDomains[host]; ok {
		return true
	}
	if dot := strings.IndexByte(host, '.'); dot >= 0 {
		if _, ok := retroSharedHostingDomains[host[dot+1:]]; ok {
			return true
		}
	}
	return false
}
