package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"gorm.io/gorm"

	"github.com/izm1chael/mailhook/auth"
	"github.com/izm1chael/mailhook/config"
	"github.com/izm1chael/mailhook/db"
	"github.com/izm1chael/mailhook/feeds"
	imaplib "github.com/izm1chael/mailhook/imap"
	"github.com/izm1chael/mailhook/metrics"
	"github.com/izm1chael/mailhook/notify"
	"github.com/izm1chael/mailhook/pipeline"
	"github.com/izm1chael/mailhook/scanners"
	"github.com/izm1chael/mailhook/storage"
	"github.com/izm1chael/mailhook/web"
	"github.com/izm1chael/mailhook/web/handlers"
)

var version = "dev"

func main() {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("config load failed", "err", err)
		os.Exit(1)
	}

	log := initLogger(cfg)
	log.Info("MailHook starting", "version", version, "accounts", len(cfg.Accounts))
	csrfFP := sha256.Sum256([]byte(cfg.CSRFSecret))
	dbKeyFP := sha256.Sum256([]byte(cfg.DBEncryptionKey))
	log.Info("secrets loaded",
		"csrf_secret_fp", hex.EncodeToString(csrfFP[:4]),
		"db_key_fp", hex.EncodeToString(dbKeyFP[:4]),
	)

	for _, dir := range []string{
		filepath.Dir(cfg.DBPath),
		filepath.Join(cfg.DataDir, "emls"),
		cfg.FeedsCacheDir,
		cfg.YARARulesDir,
	} {
		if err := os.MkdirAll(dir, 0750); err != nil {
			log.Error("failed to create runtime directory", "path", dir, "err", err)
			os.Exit(1)
		}
	}

	gdb, err := db.Open(cfg.DBPath)
	if err != nil {
		log.Error("db open failed", "err", err)
		os.Exit(1)
	}
	// Close the underlying connection so SQLite flushes WAL and removes -wal/-shm files.
	if sqlDB, err2 := gdb.DB.DB(); err2 == nil {
		defer sqlDB.Close()
	}
	if err := gdb.Migrate(); err != nil {
		log.Error("db migrate failed", "err", err)
		os.Exit(1)
	}
	if err := gdb.IntegrityCheck(); err != nil {
		log.Warn("db integrity check failed", "err", err)
	}

	// DBEncryptionKey is required (enforced by config.validate()).
	key, err := hex.DecodeString(cfg.DBEncryptionKey)
	if err != nil || len(key) != 32 {
		log.Error("MAILHOOK_DB_ENCRYPTION_KEY must be a 64-character hex string (32 bytes)", "err", err)
		os.Exit(1)
	}
	db.SetEncryptionKey(key)
	log.Info("at-rest credential encryption enabled")

	loadPersistedSettings(gdb, cfg, log)
	if cfg.NtfyURL != "" {
		if _, err := url.ParseRequestURI(cfg.NtfyURL); err != nil {
			log.Error("invalid ntfy_url loaded from DB", "err", err)
			os.Exit(1)
		}
	}
	if cfg.SpamScore >= cfg.RejectScore {
		log.Error("persisted spam_score/reject_score are invalid",
			"spam_score", cfg.SpamScore, "reject_score", cfg.RejectScore)
		os.Exit(1)
	}
	migrateAccountsToDB(gdb, cfg, log)

	if err := web.InitTemplates(); err != nil {
		log.Error("template init failed", "err", err)
		os.Exit(1)
	}

	store, err := storage.New(cfg.DataDir, log)
	if err != nil {
		log.Error("storage init failed", "err", err)
		os.Exit(1)
	}

	sessions := auth.NewStore(24 * time.Hour)
	sessions.LoadFromDB(gdb)

	// CSRFSecret is required (enforced by config.validate()).
	csrfSecret := []byte(cfg.CSRFSecret)

	authMiddleware := auth.NewMiddleware(sessions, cfg.TrustedProxies, csrfSecret, !cfg.InsecureCookies)
	rateLimiter := auth.NewLoginRateLimiter()

	hub := web.NewSSEHub()
	notifier := notify.New(cfg, log)

	// Load persisted webhook config
	{
		var webhookURL, webhookVerdicts db.AppSetting
		if err := gdb.Where("key = ?", "webhook_url").First(&webhookURL).Error; err == nil {
			if err2 := gdb.Where("key = ?", "webhook_verdicts").First(&webhookVerdicts).Error; err2 == nil {
				notifier.SetWebhook(webhookURL.Value, webhookVerdicts.Value)
			} else {
				notifier.SetWebhook(webhookURL.Value, "")
			}
		}
	}

	rspamd := scanners.NewRspamd(cfg.RspamdURL, log)
	clamav := scanners.NewClamAV(cfg.ClamAVAddr, log)
	yaraScanner, err := scanners.NewYARA(cfg.YARARulesDir, log)
	if err != nil {
		log.Error("YARA init failed", "err", err)
		os.Exit(1)
	}
	feedManager := feeds.New(cfg.FeedsCacheDir, gdb, log)
	feedManager.SetPhishTankKey(cfg.PhishTankKey)
	urlCheck := scanners.NewURLCheck(feedManager, log)
	urlUnshorten := scanners.NewURLUnshorten(feedManager, cfg, log)
	nrdCheck := scanners.NewNRDCheck(gdb, cfg, log)
	ipRep := scanners.NewIPReputation(cfg.AbuseIPDBKey, gdb, log)
	vt := scanners.NewVirusTotal(
		cfg.VTAPIKey, gdb, log,
		time.Duration(cfg.VTCacheTTLHours)*time.Hour,
		time.Duration(cfg.VTNotFoundCacheTTLHours)*time.Hour,
	)

	htmlSmuggling := scanners.NewHTMLSmuggling(cfg, log)
	hiddenText := scanners.NewHiddenTextDetect(cfg, log)
	mbScanner := scanners.NewMalwareBazaar(feedManager, log)
	onnxScanner, err := scanners.NewONNXScanner(cfg, log)
	if err != nil {
		log.Error("ONNX scanner init failed", "err", err)
		os.Exit(1)
	}
	defer onnxScanner.Close()

	allScanners := []pipeline.Scanner{rspamd, clamav, yaraScanner, urlCheck, urlUnshorten, nrdCheck, ipRep, vt, htmlSmuggling, hiddenText, mbScanner, onnxScanner}

	// Apply persisted scanner enabled states
	for _, sc := range allScanners {
		type enabler interface{ SetEnabled(bool) }
		if e, ok := sc.(enabler); ok {
			var setting db.AppSetting
			key := "scanner_" + sc.Name() + "_enabled"
			if err := gdb.Where("key = ?", key).First(&setting).Error; err == nil {
				e.SetEnabled(setting.Value != "false")
			}
		}
	}

	settingsScanners := []handlers.ScannerEnabler{rspamd, clamav, yaraScanner, urlCheck, urlUnshorten, nrdCheck, ipRep, vt, htmlSmuggling, hiddenText, mbScanner, onnxScanner}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// bgCtx is separate from the signal context so background I/O tasks (feed
	// downloads, YARA watcher) get a grace window to finish their current
	// iteration after the HTTP server stops, rather than being cut mid-write.
	bgCtx, bgCancel := context.WithCancel(context.Background())
	defer bgCancel()

	var wg sync.WaitGroup
	// pipelineWg tracks in-flight p.Process() calls so shutdown waits for them
	// to finish writing to the DB before sqlDB.Close() fires.
	var pipelineWg sync.WaitGroup

	// Global scan semaphore — shared across all pipeline instances (one per account)
	// so the total concurrent scans across all accounts is bounded by MaxConcurrentScans.
	scanSemMax := cfg.MaxConcurrentScans
	if scanSemMax <= 0 {
		scanSemMax = 20
	}
	globalScanSem := make(chan struct{}, scanSemMax)

	go func() {
		log.Info("initial feed refresh starting")
		feedManager.Refresh(bgCtx)
		log.Info("initial feed refresh complete")
	}()

	// Load accounts from DB (seeded from config.yaml above).
	var dbAccounts []db.Account
	if err := gdb.Find(&dbAccounts).Error; err != nil {
		log.Warn("could not load accounts from db", "err", err)
	}

	// registry is the single source of truth for live accounts — it maps each account
	// name to both its IMAP actions handler (for user-triggered Release/Delete) and
	// its email processor (for Rescan). Using a mutex-protected registry instead of
	// bare maps ensures concurrent account create/delete from the Settings UI is
	// race-free, and newly created accounts are immediately available for actions.
	registry := handlers.NewAccountRegistry()

	accountMgr := imaplib.NewManager(ctx, gdb, log)

	makeOnEmail := func(account config.AccountConfig) imaplib.OnEmailFn {
		// pipelineAct is used by the pipeline for automatic IMAP moves/deletes.
		pipelineAct := imaplib.NewActions(account, log)
		p := pipeline.New(allScanners, store, gdb, pipelineAct, hub, notifier, cfg, log, globalScanSem)
		// handlerAct is a separate connection used by user-triggered HTTP actions.
		handlerAct := imaplib.NewActions(account, log)
		registry.Add(account.Name, handlerAct, p)
		return func(ctx context.Context, accountName string, raw []byte, uid uint32, mailbox string) {
			pipelineWg.Add(1)
			defer pipelineWg.Done()
			p.Process(ctx, accountName, raw, uid, mailbox)
		}
	}

	for _, a := range dbAccounts {
		acfg := config.AccountConfig{
			Name: a.Name, Host: a.Host, Port: a.Port,
			User: a.User, Pass: string(a.Pass),
			Mailbox: a.Mailbox, Quarantine: a.Quarantine,
			TLSSkipVerify: a.TLSSkipVerify,
			BackfillDays:  a.BackfillDays,
		}
		act := imaplib.NewActions(acfg, log)
		if err := act.EnsureFolderExists(ctx); err != nil {
			log.Warn("could not verify quarantine folder", "account", a.Name, "err", err)
		}
		if err := accountMgr.Start(acfg, makeOnEmail(acfg)); err != nil {
			log.Warn("imap listener failed to start", "account", a.Name, "err", err)
		}
		if acfg.BackfillDays != 0 {
			makeBackfillEmail := func(account config.AccountConfig) imaplib.OnEmailFn {
				pipelineAct := imaplib.NewActions(account, log)
				p := pipeline.New(allScanners, store, gdb, pipelineAct, hub, notifier, cfg, log, globalScanSem)
				return func(ctx context.Context, accountName string, raw []byte, uid uint32, mailbox string) {
					pipelineWg.Add(1)
					defer pipelineWg.Done()
					p.ProcessBackfill(ctx, accountName, raw, uid, mailbox)
				}
			}
			bf := imaplib.NewBackfillScanner(acfg, gdb, makeBackfillEmail(acfg), log)
			wg.Add(1)
			go func() {
				defer wg.Done()
				bf.Run(bgCtx)
			}()
		}
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		feedManager.Run(bgCtx, cfg.FeedRefreshInterval)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		pipeline.NewRetroScanner(gdb, feedManager, notifier, hub, cfg, log).Run(bgCtx)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		yaraScanner.WatchRules(bgCtx)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		sessions.SweepLoop(ctx)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		t := time.NewTicker(5 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				rateLimiter.Sweep()
			case <-ctx.Done():
				return
			}
		}
	}()

	// Daily maintenance at 03:00 local time
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			delay := durationUntilHour(3)
			select {
			case <-time.After(delay):
				runDailyMaintenance(cfg, gdb, store, log)
			case <-bgCtx.Done():
				return
			}
		}
	}()

	// Prometheus gauge refresh every 30s
	wg.Add(1)
	go func() {
		defer wg.Done()
		tick := time.NewTicker(30 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-tick.C:
				updateMetricGauges(gdb, store, yaraScanner, feedManager)
			case <-bgCtx.Done():
				return
			}
		}
	}()

	healthHandler := handlers.NewHealthHandler(gdb, rspamd, clamav, feedManager, yaraScanner, version, log)
	metricsHandler, err := handlers.NewMetricsHandler(cfg.MetricsAllowedCIDRs, authMiddleware)
	if err != nil {
		log.Error("metrics handler init failed", "err", err)
		os.Exit(1)
	}
	authHandler := handlers.NewAuthHandler(cfg, sessions, rateLimiter, authMiddleware, log)
	dashHandler := handlers.NewDashboardHandler(gdb, authMiddleware, log)
	emailsHandler := handlers.NewEmailsHandler(gdb, store)
	actionsHandler := handlers.NewActionsHandler(gdb, store, registry, rspamd, log)
	allowlistsHandler := handlers.NewAllowlistsHandler(gdb, authMiddleware, log)
	settingsHandler := handlers.NewSettingsHandler(gdb, cfg, feedManager, feedManager, yaraScanner, notifier, vt, ipRep, settingsScanners, rspamd, clamav, accountMgr, makeOnEmail, registry, sessions, authMiddleware, log)
	sseHandler := handlers.NewSSEHandler(hub)

	scanHandler, err := handlers.NewScanHandler(allScanners, cfg, cfg.MetricsAllowedCIDRs, authMiddleware)
	if err != nil {
		log.Error("scan handler init failed", "err", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()

	// Static assets (embedded JS/CSS — no CDN)
	mux.Handle("GET /static/", http.StripPrefix("/static/", web.StaticHandler()))

	// Public routes
	mux.HandleFunc("GET /healthz", healthHandler.GetLiveness)
	mux.HandleFunc("GET /health", authMiddleware.Require(healthHandler.GetHealth))
	mux.HandleFunc("GET /metrics", metricsHandler.GetMetrics)
	mux.HandleFunc("GET /login", authHandler.GetLogin)
	mux.HandleFunc("POST /login", authHandler.PostLogin)
	mux.HandleFunc("POST /logout", authMiddleware.Require(authHandler.PostLogout))

	// Protected pages
	mux.HandleFunc("GET /", authMiddleware.Require(dashHandler.GetDashboard))
	mux.HandleFunc("GET /quarantine", authMiddleware.Require(dashHandler.GetQuarantine))
	mux.HandleFunc("GET /backfill", authMiddleware.Require(dashHandler.GetBackfill))
	mux.HandleFunc("GET /stats", authMiddleware.Require(dashHandler.GetStats))
	mux.HandleFunc("GET /allowlists", authMiddleware.Require(allowlistsHandler.GetAllowlists))
	mux.HandleFunc("GET /settings", authMiddleware.Require(settingsHandler.GetSettings))
	mux.HandleFunc("GET /audit", authMiddleware.Require(dashHandler.GetAuditLog))

	// API — read-only
	mux.HandleFunc("POST /api/scan", authMiddleware.Require(scanHandler.PostScan))
	mux.HandleFunc("GET /api/events", authMiddleware.Require(sseHandler.GetEvents))
	mux.HandleFunc("GET /api/scans", authMiddleware.Require(emailsHandler.ListScans))
	mux.HandleFunc("GET /api/scans/", authMiddleware.Require(emailsHandler.GetScan))
	mux.HandleFunc("GET /api/eml/", authMiddleware.Require(emailsHandler.DownloadEML))
	mux.HandleFunc("GET /api/preview/", authMiddleware.Require(emailsHandler.PreviewHTML))
	mux.HandleFunc("GET /api/defang", authMiddleware.Require(handlers.DefangURL))
	mux.HandleFunc("GET /api/whitelist", authMiddleware.Require(allowlistsHandler.ListWhitelist))
	mux.HandleFunc("GET /api/blocklist", authMiddleware.Require(allowlistsHandler.ListBlocklist))
	mux.HandleFunc("GET /api/export", authMiddleware.Require(emailsHandler.Export))

	// API — mutating (CSRF required)
	csrf := authMiddleware.CSRF
	mux.HandleFunc("POST /api/bulk-action", authMiddleware.Require(csrf(actionsHandler.BulkAction)))
	mux.HandleFunc("POST /api/release/", authMiddleware.Require(csrf(actionsHandler.Release)))
	mux.HandleFunc("POST /api/release-learn/", authMiddleware.Require(csrf(actionsHandler.ReleaseAndLearn)))
	mux.HandleFunc("POST /api/delete/", authMiddleware.Require(csrf(actionsHandler.Delete)))
	mux.HandleFunc("POST /api/quarantine/", authMiddleware.Require(csrf(actionsHandler.Quarantine)))
	mux.HandleFunc("POST /api/learn-spam/", authMiddleware.Require(csrf(actionsHandler.LearnSpam)))
	mux.HandleFunc("POST /api/rescan/", authMiddleware.Require(csrf(actionsHandler.Rescan)))
	mux.HandleFunc("POST /api/whitelist", authMiddleware.Require(csrf(allowlistsHandler.AddWhitelist)))
	mux.HandleFunc("DELETE /api/whitelist/", authMiddleware.Require(csrf(allowlistsHandler.DeleteWhitelist)))
	mux.HandleFunc("POST /api/blocklist", authMiddleware.Require(csrf(allowlistsHandler.AddBlocklist)))
	mux.HandleFunc("DELETE /api/blocklist/", authMiddleware.Require(csrf(allowlistsHandler.DeleteBlocklist)))
	mux.HandleFunc("POST /api/allowlists/bulk-import", authMiddleware.Require(csrf(allowlistsHandler.BulkImport)))
	mux.HandleFunc("POST /api/settings/thresholds", authMiddleware.Require(csrf(settingsHandler.UpdateThresholds)))
	mux.HandleFunc("POST /api/settings/notify-test", authMiddleware.Require(csrf(settingsHandler.NotifyTest)))
	mux.HandleFunc("POST /api/settings/feeds-refresh", authMiddleware.Require(csrf(settingsHandler.FeedsRefresh)))
	mux.HandleFunc("POST /api/settings/yara-reload", authMiddleware.Require(csrf(settingsHandler.YARAReload)))
	mux.HandleFunc("POST /api/settings/api-keys", authMiddleware.Require(csrf(settingsHandler.UpdateAPIKeys)))
	mux.HandleFunc("POST /api/settings/notifications", authMiddleware.Require(csrf(settingsHandler.UpdateNotifications)))
	mux.HandleFunc("POST /api/settings/webhook", authMiddleware.Require(csrf(settingsHandler.UpdateWebhook)))
	mux.HandleFunc("POST /api/settings/password", authMiddleware.Require(csrf(settingsHandler.ChangePassword)))
	mux.HandleFunc("GET /api/settings/custom-feed", authMiddleware.Require(settingsHandler.ListCustomFeed))
	mux.HandleFunc("POST /api/settings/custom-feed", authMiddleware.Require(csrf(settingsHandler.AddCustomFeed)))
	mux.HandleFunc("DELETE /api/settings/custom-feed/", authMiddleware.Require(csrf(settingsHandler.DeleteCustomFeed)))
	mux.HandleFunc("POST /api/settings/scanners", authMiddleware.Require(csrf(settingsHandler.UpdateScanners)))
	mux.HandleFunc("POST /api/settings/endpoints", authMiddleware.Require(csrf(settingsHandler.UpdateEndpoints)))
	mux.HandleFunc("GET /api/settings/accounts", authMiddleware.Require(settingsHandler.GetAccounts))
	mux.HandleFunc("POST /api/settings/accounts/test", authMiddleware.Require(csrf(settingsHandler.TestAccount)))
	mux.HandleFunc("POST /api/settings/accounts", authMiddleware.Require(csrf(settingsHandler.CreateAccount)))
	mux.HandleFunc("PUT /api/settings/accounts/", authMiddleware.Require(csrf(settingsHandler.UpdateAccount)))
	mux.HandleFunc("DELETE /api/settings/accounts/", authMiddleware.Require(csrf(settingsHandler.DeleteAccount)))

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           web.Recovery(log, web.SecurityHeaders(mux)),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		<-ctx.Done()
		log.Info("shutdown: stopping HTTP")
		// Drain HTTP first so no new sessions can be created, then persist.
		shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		srv.Shutdown(shutCtx) //nolint:errcheck
		// Persist sessions after the HTTP drain — no new logins can land at this point.
		sessions.PersistToDB(gdb) //nolint:errcheck
		// Stage 2: cancel background tasks immediately; they honour their own contexts.
		log.Info("shutdown: cancelling background tasks")
		bgCancel()
		// Stage 3: wait for all in-flight p.Process() pipeline goroutines to finish
		// writing their scan records before sqlDB.Close() fires.
		log.Info("shutdown: draining in-flight pipeline scans")
		pipelineWg.Wait()
	}()

	log.Info("HTTP server listening", "addr", cfg.ListenAddr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Error("server error", "err", err)
	}

	waitCh := make(chan struct{})
	go func() { wg.Wait(); close(waitCh) }()
	select {
	case <-waitCh:
		log.Info("MailHook shutdown complete")
	case <-time.After(30 * time.Second):
		log.Warn("MailHook shutdown timed out — forcing exit")
	}
}

// durationUntilHour returns the time until the next occurrence of hour:00 local time.
func durationUntilHour(hour int) time.Duration {
	now := time.Now()
	next := time.Date(now.Year(), now.Month(), now.Day(), hour, 0, 0, 0, now.Location())
	if !next.After(now) {
		next = next.Add(24 * time.Hour)
	}
	return time.Until(next)
}

// runDailyMaintenance runs all scheduled DB/EML/backup tasks.
func runDailyMaintenance(cfg *config.Config, gdb *db.DB, store *storage.Store, log *slog.Logger) {
	log.Info("daily maintenance starting")

	// EML retention for clean mail (only stored when EMLCleanRetain=true).
	// Quarantined EML paths are excluded — they have their own longer retention below.
	if cfg.EMLCleanRetain && cfg.RetentionDays > 0 {
		var quarantinedPaths []string
		gdb.Model(&db.Scan{}).
			Where("status = ? AND eml_path != ''", db.StatusQuarantined).
			Pluck("eml_path", &quarantinedPaths)
		quarantineSet := make(map[string]struct{}, len(quarantinedPaths))
		for _, p := range quarantinedPaths {
			quarantineSet[p] = struct{}{}
		}
		age := time.Duration(cfg.RetentionDays) * 24 * time.Hour
		if n, err := store.PurgeOlderThan(age, quarantineSet); err != nil {
			log.Warn("eml clean retention error", "err", err)
		} else if n > 0 {
			log.Info("eml clean retention", "deleted", n, "retention_days", cfg.RetentionDays)
		}
	}

	// EML retention for quarantined mail (longer retention)
	if cfg.EMLQuarantineRetentionDays > 0 {
		cutoff := time.Now().AddDate(0, 0, -cfg.EMLQuarantineRetentionDays)
		var oldScans []db.Scan
		gdb.Where("status = ? AND created_at < ? AND eml_path != ''",
			db.StatusQuarantined, cutoff).
			Select("id, eml_path").Find(&oldScans)

		deleted := 0
		for _, s := range oldScans {
			if err := store.Delete(s.EMLPath); err == nil {
				gdb.Write(func(tx *gorm.DB) error { //nolint:errcheck
					return tx.Model(&db.Scan{}).Where("id = ?", s.ID).
						Update("eml_path", "").Error
				})
				deleted++
			}
		}
		if deleted > 0 {
			log.Info("quarantined eml retention", "deleted", deleted,
				"retention_days", cfg.EMLQuarantineRetentionDays)
		}
	}

	// IP reputation cache 7-day sweep
	cutoff7d := time.Now().Add(-7 * 24 * time.Hour)
	gdb.Write(func(tx *gorm.DB) error { //nolint:errcheck
		return tx.Where("fetched_at < ?", cutoff7d).Delete(&db.IPReputationCache{}).Error
	})

	// NRD cache sweep: remove expired entries
	gdb.Write(func(tx *gorm.DB) error { //nolint:errcheck
		return tx.Where("expires_at < ?", time.Now()).Delete(&db.NRDCache{}).Error
	})

	// VT hash cache: remove entries older than 7 days to prevent unbounded growth.
	// Active entries are kept alive by the TTL check in lookupHash.
	gdb.Write(func(tx *gorm.DB) error { //nolint:errcheck
		return tx.Where("fetched_at < ?", time.Now().Add(-7*24*time.Hour)).Delete(&db.VTHashCache{}).Error
	})

	// Daily backup via VACUUM INTO
	backupPath := filepath.Join(cfg.DataDir,
		fmt.Sprintf("mailhook-backup-%s.db", time.Now().Format("2006-01-02")))
	if err := gdb.VacuumInto(backupPath); err != nil {
		log.Warn("db backup failed", "err", err)
	} else {
		log.Info("db backup complete", "path", backupPath)
	}

	// Rotate old backups — keep 7 days
	if matches, err := filepath.Glob(filepath.Join(cfg.DataDir, "mailhook-backup-*.db")); err == nil {
		cutoff := time.Now().AddDate(0, 0, -7)
		for _, f := range matches {
			base := filepath.Base(f)
			dateStr := strings.TrimPrefix(strings.TrimSuffix(base, ".db"), "mailhook-backup-")
			if t, err2 := time.Parse("2006-01-02", dateStr); err2 == nil && t.Before(cutoff) {
				if err3 := os.Remove(f); err3 == nil {
					log.Info("db backup rotated", "path", f)
				} else {
					log.Warn("db backup rotation failed", "path", f, "err", err3)
				}
			}
		}
	}

	// Orphan EML sweep: remove files on disk with no matching DB record.
	// Catches EMLs written before a DB insert that then failed/panicked.
	var emlPaths []string
	gdb.Model(&db.Scan{}).Where("eml_path != ''").Pluck("eml_path", &emlPaths)
	known := make(map[string]struct{}, len(emlPaths))
	for _, p := range emlPaths {
		known[p] = struct{}{}
	}
	if n, err := store.ReconcileOrphans(known); err == nil && n > 0 {
		log.Info("orphaned eml files removed", "count", n)
	} else if err != nil {
		log.Warn("orphan reconciliation error", "err", err)
	}

	// Incremental page reclaim — releases a small batch of free pages without
	// acquiring an exclusive lock. A full VACUUM can take 15–30 s on large DBs
	// and blocks all pipeline writes for its duration; incremental_vacuum reclaims
	// 1000 pages at a time (typically < 1 ms) while WAL mode stays fully active.
	// auto_vacuum=INCREMENTAL is set in the DSN; if a legacy DB still has
	// auto_vacuum=NONE the pragma is silently a no-op — no harm done.
	if err := gdb.DB.Exec("PRAGMA incremental_vacuum(1000)").Error; err != nil {
		log.Warn("incremental vacuum failed", "err", err)
	}

	log.Info("daily maintenance complete")
}

// updateMetricGauges refreshes Prometheus gauges that require periodic sampling.
func updateMetricGauges(gdb *db.DB, store *storage.Store, yara *scanners.YARA, feedMgr *feeds.Manager) {
	if n, err := store.DirSize(); err == nil {
		metrics.EMLStoreSizeBytes.Set(float64(n))
	}
	if n, err := gdb.Size(); err == nil {
		metrics.DBSizeBytes.Set(float64(n))
	}

	var count int64
	gdb.Model(&db.Scan{}).Where("status = ?", db.StatusQuarantined).Count(&count)
	metrics.QuarantineQueueTotal.Set(float64(count))

	metrics.YARARulesTotal.Set(float64(yara.RuleCount()))

	counts, _ := feedMgr.FeedStats()
	for feed, n := range counts {
		metrics.FeedEntriesTotal.WithLabelValues(feed).Set(float64(n))
	}

	var mbCount int64
	gdb.Model(&db.MalwareBazaarHash{}).Count(&mbCount)
	metrics.FeedEntriesTotal.WithLabelValues("malwarebazaar").Set(float64(mbCount))
}

// loadPersistedSettings overrides config values from AppSetting DB rows if present.
func loadPersistedSettings(gdb *db.DB, cfg *config.Config, log *slog.Logger) {
	loadStr := func(key string, apply func(string)) {
		var s db.AppSetting
		if err := gdb.Where("key = ?", key).First(&s).Error; err == nil && s.Value != "" {
			apply(s.Value)
		}
	}
	loadFloat := func(key string, apply func(float64)) {
		var s db.AppSetting
		if err := gdb.Where("key = ?", key).First(&s).Error; err == nil {
			if v, err2 := strconv.ParseFloat(s.Value, 64); err2 == nil && v > 0 {
				apply(v)
			}
		}
	}
	loadSecret := func(key string, apply func(string)) {
		var s db.AppSetting
		if err := gdb.Where("key = ?", key).First(&s).Error; err == nil && s.Value != "" {
			var es db.EncryptedString
			if err2 := es.Scan(s.Value); err2 == nil {
				apply(string(es))
			}
		}
	}
	loadFloat("spam_score", func(v float64) { log.Info("loaded spam_score from db", "value", v); cfg.SetSpamScore(v) })
	loadFloat("reject_score", func(v float64) { log.Info("loaded reject_score from db", "value", v); cfg.SetRejectScore(v) })
	loadSecret("ntfy_url", func(v string) { cfg.NtfyURL = v })
	loadStr("ntfy_topic", func(v string) { cfg.NtfyTopic = v })
	loadSecret("ntfy_token", func(v string) { cfg.NtfyToken = v })
	loadSecret("vt_api_key", func(v string) { cfg.VTAPIKey = v })
	loadSecret("abuseipdb_key", func(v string) { cfg.AbuseIPDBKey = v })
	loadSecret("phishtank_key", func(v string) { cfg.PhishTankKey = v })
	loadStr("rspamd_url", func(v string) { cfg.RspamdURL = v })
	loadStr("clamav_addr", func(v string) { cfg.ClamAVAddr = v })
	loadStr("yara_rules_dir", func(v string) { cfg.YARARulesDir = v })
	loadStr("admin_password_bcrypt", func(v string) { cfg.SetAdminPasswordBcrypt(v) })
}

// migrateAccountsToDB upserts all accounts from config.yaml into the DB on every start.
// YAML always wins — if a credential is rotated in the config file the DB row is updated.
// Accounts managed exclusively via the Settings UI should be removed from config.yaml
// to avoid overwriting UI changes on restart.
func migrateAccountsToDB(gdb *db.DB, cfg *config.Config, log *slog.Logger) {
	for _, a := range cfg.Accounts {
		acc := db.Account{
			Name: a.Name, Host: a.Host, Port: a.Port,
			User: a.User, Pass: db.EncryptedString(a.Pass),
			Mailbox: a.Mailbox, Quarantine: a.Quarantine,
			TLSSkipVerify: a.TLSSkipVerify,
			BackfillDays:  a.BackfillDays,
		}
		if err := gdb.Write(func(tx *gorm.DB) error {
			return tx.Save(&acc).Error
		}); err != nil {
			log.Warn("account upsert failed", "account", a.Name, "err", err)
		}
	}
}

func initLogger(cfg *config.Config) *slog.Logger {
	var level slog.Level
	switch cfg.LogLevel {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{Level: level}
	var h slog.Handler
	if cfg.LogFormat == "text" {
		h = slog.NewTextHandler(os.Stdout, opts)
	} else {
		h = slog.NewJSONHandler(os.Stdout, opts)
	}
	return slog.New(h)
}
