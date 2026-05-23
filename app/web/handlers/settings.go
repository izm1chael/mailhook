package handlers

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"github.com/izm1chael/mailhook/auth"
	"github.com/izm1chael/mailhook/config"
	"github.com/izm1chael/mailhook/db"
	imaplib "github.com/izm1chael/mailhook/imap"
	"github.com/izm1chael/mailhook/notify"
	"github.com/izm1chael/mailhook/web"
)

// FeedRefresher can trigger an immediate feed refresh.
type FeedRefresher interface {
	Refresh(ctx context.Context)
}

// YARAReloader can reload YARA rules from disk on demand.
type YARAReloader interface {
	ReloadRules() error
	SetRulesDir(dir string) error
}

// APIKeyUpdater allows runtime API key rotation without restarting.
type APIKeyUpdater interface {
	SetAPIKey(key string)
}

// ScannerEnabler allows the settings UI to enable or disable individual scanners at runtime.
type ScannerEnabler interface {
	Name() string
	IsEnabled() bool
	SetEnabled(enabled bool)
}

// RspamdURLSetter allows updating the Rspamd endpoint URL at runtime.
type RspamdURLSetter interface {
	SetURL(url string)
}

// ClamAVAddrSetter allows updating the ClamAV daemon address at runtime.
type ClamAVAddrSetter interface {
	SetAddr(addr string)
}

// AccountManager manages live IMAP listener goroutines.
type AccountManager interface {
	Start(account config.AccountConfig, onEmail imaplib.OnEmailFn) error
	Stop(name string)
	Restart(account config.AccountConfig, onEmail imaplib.OnEmailFn) error
	IsRunning(name string) bool
	Test(ctx context.Context, account config.AccountConfig) error
}

// OnEmailFactory creates the per-account email processing callback.
type OnEmailFactory func(config.AccountConfig) imaplib.OnEmailFn

// SessionInvalidator can invalidate all active sessions (e.g. after a password change).
type SessionInvalidator interface {
	DeleteAll()
}

// SettingsHandler serves the settings page and settings mutation API.
type SettingsHandler struct {
	gdb        *db.DB
	cfg        *config.Config
	feeds      FeedRefresher
	yara       YARAReloader
	notifier   *notify.Notifier
	vt         APIKeyUpdater
	ipRep      APIKeyUpdater
	scanners   []ScannerEnabler
	rspamd     RspamdURLSetter
	clamav     ClamAVAddrSetter
	accountMgr AccountManager
	makeEmail  OnEmailFactory
	registry   *AccountRegistry
	sessions   SessionInvalidator
	middleware *auth.Middleware
	log        *slog.Logger
}

// NewSettingsHandler creates a SettingsHandler.
func NewSettingsHandler(
	gdb *db.DB,
	cfg *config.Config,
	feeds FeedRefresher,
	yara YARAReloader,
	notifier *notify.Notifier,
	vt APIKeyUpdater,
	ipRep APIKeyUpdater,
	scanners []ScannerEnabler,
	rspamd RspamdURLSetter,
	clamav ClamAVAddrSetter,
	accountMgr AccountManager,
	makeEmail OnEmailFactory,
	registry *AccountRegistry,
	sessions SessionInvalidator,
	middleware *auth.Middleware,
	log *slog.Logger,
) *SettingsHandler {
	return &SettingsHandler{
		gdb: gdb, cfg: cfg, feeds: feeds, yara: yara, notifier: notifier,
		vt: vt, ipRep: ipRep, scanners: scanners,
		rspamd: rspamd, clamav: clamav,
		accountMgr: accountMgr, makeEmail: makeEmail,
		registry:   registry,
		sessions:   sessions,
		middleware: middleware,
		log:        log,
	}
}

type scannerState struct {
	Name    string
	Enabled bool
}

// GetSettings renders the settings page.
func (h *SettingsHandler) GetSettings(w http.ResponseWriter, r *http.Request) {
	csrfToken := csrfFromRequest(h.middleware, w, r)
	var scannerStates []scannerState
	for _, s := range h.scanners {
		scannerStates = append(scannerStates, scannerState{Name: s.Name(), Enabled: s.IsEnabled()})
	}
	web.Render(w, r, "settings.html", map[string]interface{}{
		"CSRFToken":       csrfToken,
		"SpamScore":       h.cfg.SpamScore,
		"RejectScore":     h.cfg.RejectScore,
		"NtfyURL":         h.cfg.NtfyURL,
		"NtfyTopic":       h.cfg.NtfyTopic,
		"VTConfigured":    h.cfg.VTAPIKey != "",
		"IPRepConfigured": h.cfg.AbuseIPDBKey != "",
		"RspamdURL":       h.cfg.RspamdURL,
		"ClamAVAddr":      h.cfg.ClamAVAddr,
		"YARARulesDir":    h.cfg.YARARulesDir,
		"DataDir":         h.cfg.DataDir,
		"Nav":             "settings",
		"Scanners":        scannerStates,
	})
}

// UpdateThresholds handles POST /api/settings/thresholds
// Updates spam/reject score thresholds in memory for the current process lifetime.
func (h *SettingsHandler) UpdateThresholds(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SpamScore   float64 `json:"spam_score"`
		RejectScore float64 `json:"reject_score"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.SpamScore <= 0 || req.RejectScore <= 0 || req.SpamScore >= req.RejectScore {
		respondJSON(w, http.StatusBadRequest, map[string]string{
			"error": "spam_score must be > 0 and < reject_score",
		})
		return
	}
	h.cfg.SetSpamScore(req.SpamScore)
	h.cfg.SetRejectScore(req.RejectScore)

	actor := actorFromRequest(r)
	now := time.Now()
	h.gdb.Write(func(tx *gorm.DB) error { //nolint:errcheck
		tx.Save(&db.AppSetting{Key: "spam_score", Value: fmt.Sprintf("%.4f", req.SpamScore), UpdatedAt: now, UpdatedBy: actor})
		tx.Save(&db.AppSetting{Key: "reject_score", Value: fmt.Sprintf("%.4f", req.RejectScore), UpdatedAt: now, UpdatedBy: actor})
		return nil
	})

	h.log.Info("thresholds updated", "spam", req.SpamScore, "reject", req.RejectScore, "by", actor)
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"spam_score":   h.cfg.GetSpamScore(),
		"reject_score": h.cfg.GetRejectScore(),
	})
}

// encryptSetting encrypts plaintext using EncryptedString (AES-256-GCM) when a
// key is configured; returns plaintext unchanged if no encryption key is set.
func encryptSetting(plaintext string) string {
	es := db.EncryptedString(plaintext)
	v, err := es.Value()
	if err != nil || v == nil {
		return plaintext
	}
	if s, ok := v.(string); ok {
		return s
	}
	return plaintext
}

// UpdateAPIKeys handles POST /api/settings/api-keys
// Persists VirusTotal and AbuseIPDB keys to DB and applies them immediately.
func (h *SettingsHandler) UpdateAPIKeys(w http.ResponseWriter, r *http.Request) {
	var req struct {
		VTAPIKey     string `json:"vt_api_key"`
		AbuseIPDBKey string `json:"abuseipdb_key"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	actor := actorFromRequest(r)
	now := time.Now()
	if err := h.gdb.Write(func(tx *gorm.DB) error {
		if err := tx.Save(&db.AppSetting{Key: "vt_api_key", Value: encryptSetting(req.VTAPIKey), UpdatedAt: now, UpdatedBy: actor}).Error; err != nil {
			return err
		}
		return tx.Save(&db.AppSetting{Key: "abuseipdb_key", Value: encryptSetting(req.AbuseIPDBKey), UpdatedAt: now, UpdatedBy: actor}).Error
	}); err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]string{"error": "db write failed"})
		return
	}
	h.cfg.VTAPIKey = req.VTAPIKey
	h.cfg.AbuseIPDBKey = req.AbuseIPDBKey
	if h.vt != nil {
		h.vt.SetAPIKey(req.VTAPIKey)
	}
	if h.ipRep != nil {
		h.ipRep.SetAPIKey(req.AbuseIPDBKey)
	}
	h.log.Info("api keys updated", "by", actor)
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"vt_configured":    h.cfg.VTAPIKey != "",
		"ipRep_configured": h.cfg.AbuseIPDBKey != "",
	})
}

// UpdateNotifications handles POST /api/settings/notifications
// Persists ntfy configuration to DB and applies it immediately (Notifier reads cfg).
func (h *SettingsHandler) UpdateNotifications(w http.ResponseWriter, r *http.Request) {
	var req struct {
		NtfyURL   string `json:"ntfy_url"`
		NtfyTopic string `json:"ntfy_topic"`
		NtfyToken string `json:"ntfy_token"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	actor := actorFromRequest(r)
	now := time.Now()
	if err := h.gdb.Write(func(tx *gorm.DB) error {
		if err := tx.Save(&db.AppSetting{Key: "ntfy_url", Value: encryptSetting(req.NtfyURL), UpdatedAt: now, UpdatedBy: actor}).Error; err != nil {
			return err
		}
		if err := tx.Save(&db.AppSetting{Key: "ntfy_topic", Value: req.NtfyTopic, UpdatedAt: now, UpdatedBy: actor}).Error; err != nil {
			return err
		}
		return tx.Save(&db.AppSetting{Key: "ntfy_token", Value: encryptSetting(req.NtfyToken), UpdatedAt: now, UpdatedBy: actor}).Error
	}); err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]string{"error": "db write failed"})
		return
	}
	h.cfg.NtfyURL = req.NtfyURL
	h.cfg.NtfyTopic = req.NtfyTopic
	h.cfg.NtfyToken = req.NtfyToken
	h.log.Info("notifications updated", "by", actor)
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"ntfy_url":   h.cfg.NtfyURL,
		"ntfy_topic": h.cfg.NtfyTopic,
		"enabled":    h.cfg.NtfyURL != "",
	})
}

// NotifyTest handles POST /api/settings/notify-test
// Sends a test notification to confirm ntfy is reachable.
func (h *SettingsHandler) NotifyTest(w http.ResponseWriter, r *http.Request) {
	if h.notifier == nil || h.cfg.NtfyURL == "" {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "notifications not configured"})
		return
	}
	if err := h.notifier.SendTest(r.Context()); err != nil {
		h.log.Warn("notify test failed", "err", err)
		respondJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	respondJSON(w, http.StatusOK, map[string]string{"status": "sent"})
}

// FeedsRefresh handles POST /api/settings/feeds-refresh
// Triggers an immediate out-of-band threat feed refresh.
func (h *SettingsHandler) FeedsRefresh(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Minute)
	go func() {
		defer cancel()
		h.feeds.Refresh(ctx)
	}()
	respondJSON(w, http.StatusAccepted, map[string]string{"status": "refresh triggered"})
}

// YARAReload handles POST /api/settings/yara-reload
// Recompiles YARA rules from disk without restarting the process.
func (h *SettingsHandler) YARAReload(w http.ResponseWriter, r *http.Request) {
	if err := h.yara.ReloadRules(); err != nil {
		h.log.Warn("YARA reload failed", "err", err)
		respondJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	respondJSON(w, http.StatusOK, map[string]string{"status": "reloaded"})
}

// UpdateScanners handles POST /api/settings/scanners
// Enables or disables individual scanners at runtime.
func (h *SettingsHandler) UpdateScanners(w http.ResponseWriter, r *http.Request) {
	var req map[string]bool // scanner name → enabled
	if !decodeJSON(w, r, &req) {
		return
	}
	actor := actorFromRequest(r)
	now := time.Now()
	result := make(map[string]bool)
	for _, s := range h.scanners {
		if enabled, ok := req[s.Name()]; ok {
			s.SetEnabled(enabled)
			key := "scanner_" + s.Name() + "_enabled"
			val := "false"
			if enabled {
				val = "true"
			}
			h.gdb.Write(func(tx *gorm.DB) error { //nolint:errcheck
				return tx.Save(&db.AppSetting{Key: key, Value: val, UpdatedAt: now, UpdatedBy: actor}).Error
			})
		}
		result[s.Name()] = s.IsEnabled()
	}
	h.log.Info("scanners updated", "by", actor, "states", result)
	respondJSON(w, http.StatusOK, result)
}

// UpdateEndpoints handles POST /api/settings/endpoints
// Updates rspamd URL, ClamAV address, and YARA rules directory at runtime.
func (h *SettingsHandler) UpdateEndpoints(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RspamdURL    string `json:"rspamd_url"`
		ClamAVAddr   string `json:"clamav_addr"`
		YARARulesDir string `json:"yara_rules_dir"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	actor := actorFromRequest(r)
	now := time.Now()
	if err := h.gdb.Write(func(tx *gorm.DB) error {
		if err := tx.Save(&db.AppSetting{Key: "rspamd_url", Value: req.RspamdURL, UpdatedAt: now, UpdatedBy: actor}).Error; err != nil {
			return err
		}
		if err := tx.Save(&db.AppSetting{Key: "clamav_addr", Value: req.ClamAVAddr, UpdatedAt: now, UpdatedBy: actor}).Error; err != nil {
			return err
		}
		return tx.Save(&db.AppSetting{Key: "yara_rules_dir", Value: req.YARARulesDir, UpdatedAt: now, UpdatedBy: actor}).Error
	}); err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]string{"error": "db write failed"})
		return
	}
	if req.RspamdURL != "" {
		h.cfg.RspamdURL = req.RspamdURL
		if h.rspamd != nil {
			h.rspamd.SetURL(req.RspamdURL)
		}
	}
	if req.ClamAVAddr != "" {
		h.cfg.ClamAVAddr = req.ClamAVAddr
		if h.clamav != nil {
			h.clamav.SetAddr(req.ClamAVAddr)
		}
	}
	if req.YARARulesDir != "" {
		h.cfg.YARARulesDir = req.YARARulesDir
		if h.yara != nil {
			if err := h.yara.SetRulesDir(req.YARARulesDir); err != nil {
				h.log.Warn("YARA reload after dir change failed", "err", err)
			}
		}
	}
	h.log.Info("endpoints updated", "by", actor)
	respondJSON(w, http.StatusOK, map[string]string{
		"rspamd_url":     h.cfg.RspamdURL,
		"clamav_addr":    h.cfg.ClamAVAddr,
		"yara_rules_dir": h.cfg.YARARulesDir,
	})
}

type accountResponse struct {
	Name          string `json:"name"`
	Host          string `json:"host"`
	Port          int    `json:"port"`
	User          string `json:"user"`
	Mailbox       string `json:"mailbox"`
	Quarantine    string `json:"quarantine"`
	TLSSkipVerify bool   `json:"tls_skip_verify"`
	Running       bool   `json:"running"`
}

// GetAccounts handles GET /api/settings/accounts
func (h *SettingsHandler) GetAccounts(w http.ResponseWriter, r *http.Request) {
	var accounts []db.Account
	if err := h.gdb.Find(&accounts).Error; err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]string{"error": "db error"})
		return
	}
	resp := make([]accountResponse, 0, len(accounts))
	for _, a := range accounts {
		resp = append(resp, accountResponse{
			Name: a.Name, Host: a.Host, Port: a.Port,
			User: a.User, Mailbox: a.Mailbox, Quarantine: a.Quarantine,
			TLSSkipVerify: a.TLSSkipVerify,
			Running:       h.accountMgr != nil && h.accountMgr.IsRunning(a.Name),
		})
	}
	respondJSON(w, http.StatusOK, resp)
}

// CreateAccount handles POST /api/settings/accounts
func (h *SettingsHandler) CreateAccount(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name          string `json:"name"`
		Host          string `json:"host"`
		Port          int    `json:"port"`
		User          string `json:"user"`
		Pass          string `json:"pass"`
		Mailbox       string `json:"mailbox"`
		Quarantine    string `json:"quarantine"`
		TLSSkipVerify bool   `json:"tls_skip_verify"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Name == "" || req.Host == "" || req.User == "" || req.Pass == "" {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "name, host, user, and pass are required"})
		return
	}
	if strings.ContainsAny(req.Name, " /\\") {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "name must not contain spaces or slashes"})
		return
	}
	if req.Port == 0 {
		req.Port = 993
	}
	if req.Mailbox == "" {
		req.Mailbox = "INBOX"
	}
	if req.Quarantine == "" {
		req.Quarantine = "Quarantine"
	}

	acc := db.Account{
		Name: req.Name, Host: req.Host, Port: req.Port,
		User: req.User, Pass: db.EncryptedString(req.Pass),
		Mailbox: req.Mailbox, Quarantine: req.Quarantine,
		TLSSkipVerify: req.TLSSkipVerify,
	}
	if err := h.gdb.Write(func(tx *gorm.DB) error {
		return tx.Create(&acc).Error
	}); err != nil {
		respondJSON(w, http.StatusConflict, map[string]string{"error": "account name already exists"})
		return
	}

	cfg := config.AccountConfig{
		Name: acc.Name, Host: acc.Host, Port: acc.Port,
		User: acc.User, Pass: string(acc.Pass),
		Mailbox: acc.Mailbox, Quarantine: acc.Quarantine,
		TLSSkipVerify: acc.TLSSkipVerify,
	}
	if h.accountMgr != nil && h.makeEmail != nil {
		if err := h.accountMgr.Start(cfg, h.makeEmail(cfg)); err != nil {
			h.log.Warn("account created but listener failed to start", "account", acc.Name, "err", err)
		}
	}
	h.log.Info("account created", "account", acc.Name, "by", actorFromRequest(r))
	respondJSON(w, http.StatusCreated, accountResponse{
		Name: acc.Name, Host: acc.Host, Port: acc.Port,
		User: acc.User, Mailbox: acc.Mailbox, Quarantine: acc.Quarantine,
		TLSSkipVerify: acc.TLSSkipVerify,
		Running:       h.accountMgr != nil && h.accountMgr.IsRunning(acc.Name),
	})
}

// UpdateAccount handles PUT /api/settings/accounts/{name}
func (h *SettingsHandler) UpdateAccount(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/api/settings/accounts/")
	if name == "" {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "account name required"})
		return
	}
	var req struct {
		Host          string `json:"host"`
		Port          int    `json:"port"`
		User          string `json:"user"`
		Pass          string `json:"pass"`
		Mailbox       string `json:"mailbox"`
		Quarantine    string `json:"quarantine"`
		TLSSkipVerify *bool  `json:"tls_skip_verify"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	var acc db.Account
	if err := h.gdb.Where("name = ?", name).First(&acc).Error; err != nil {
		respondJSON(w, http.StatusNotFound, map[string]string{"error": "account not found"})
		return
	}
	if req.Host != "" {
		acc.Host = req.Host
	}
	if req.Port != 0 {
		acc.Port = req.Port
	}
	if req.User != "" {
		acc.User = req.User
	}
	if req.Pass != "" {
		acc.Pass = db.EncryptedString(req.Pass)
	}
	if req.Mailbox != "" {
		acc.Mailbox = req.Mailbox
	}
	if req.Quarantine != "" {
		acc.Quarantine = req.Quarantine
	}
	if req.TLSSkipVerify != nil {
		acc.TLSSkipVerify = *req.TLSSkipVerify
	}
	if err := h.gdb.Write(func(tx *gorm.DB) error {
		return tx.Save(&acc).Error
	}); err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]string{"error": "db error"})
		return
	}
	cfg := config.AccountConfig{
		Name: acc.Name, Host: acc.Host, Port: acc.Port,
		User: acc.User, Pass: string(acc.Pass),
		Mailbox: acc.Mailbox, Quarantine: acc.Quarantine,
		TLSSkipVerify: acc.TLSSkipVerify,
	}
	if h.accountMgr != nil && h.makeEmail != nil {
		if err := h.accountMgr.Restart(cfg, h.makeEmail(cfg)); err != nil {
			h.log.Warn("account updated but listener restart failed", "account", acc.Name, "err", err)
		}
	}
	h.log.Info("account updated", "account", acc.Name, "by", actorFromRequest(r))
	respondJSON(w, http.StatusOK, accountResponse{
		Name: acc.Name, Host: acc.Host, Port: acc.Port,
		User: acc.User, Mailbox: acc.Mailbox, Quarantine: acc.Quarantine,
		TLSSkipVerify: acc.TLSSkipVerify,
		Running:       h.accountMgr != nil && h.accountMgr.IsRunning(acc.Name),
	})
}

// DeleteAccount handles DELETE /api/settings/accounts/{name}
func (h *SettingsHandler) DeleteAccount(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/api/settings/accounts/")
	if name == "" {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "account name required"})
		return
	}
	if err := h.gdb.Write(func(tx *gorm.DB) error {
		return tx.Delete(&db.Account{}, "name = ?", name).Error
	}); err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]string{"error": "db error"})
		return
	}
	if h.accountMgr != nil {
		h.accountMgr.Stop(name)
	}
	if h.registry != nil {
		h.registry.Remove(name)
	}
	h.log.Info("account deleted", "account", name, "by", actorFromRequest(r))
	respondJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// UpdateWebhook handles POST /api/settings/webhook
// Configures the outbound webhook URL and verdict filter.
func (h *SettingsHandler) UpdateWebhook(w http.ResponseWriter, r *http.Request) {
	var req struct {
		URL      string `json:"url"`
		Verdicts string `json:"verdicts"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	actor := actorFromRequest(r)
	now := time.Now()
	if err := h.gdb.Write(func(tx *gorm.DB) error {
		if err := tx.Save(&db.AppSetting{Key: "webhook_url", Value: req.URL, UpdatedAt: now, UpdatedBy: actor}).Error; err != nil {
			return err
		}
		return tx.Save(&db.AppSetting{Key: "webhook_verdicts", Value: req.Verdicts, UpdatedAt: now, UpdatedBy: actor}).Error
	}); err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]string{"error": "db write failed"})
		return
	}
	if h.notifier != nil {
		h.notifier.SetWebhook(req.URL, req.Verdicts)
	}
	h.log.Info("webhook updated", "by", actor)
	respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ChangePassword handles POST /api/settings/password
// Verifies the current password and replaces the bcrypt hash.
func (h *SettingsHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Current string `json:"current"`
		New     string `json:"new"`
		Confirm string `json:"confirm"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(h.cfg.GetAdminPasswordBcrypt()), []byte(req.Current)); err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "current password incorrect"})
		return
	}
	if req.New != req.Confirm {
		respondJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "passwords do not match"})
		return
	}
	if len(req.New) < 12 {
		respondJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "password must be at least 12 characters"})
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.New), bcrypt.DefaultCost)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]string{"error": "hash error"})
		return
	}
	actor := actorFromRequest(r)
	now := time.Now()
	h.gdb.Write(func(tx *gorm.DB) error { //nolint:errcheck
		tx.Save(&db.AppSetting{Key: "admin_password_bcrypt", Value: string(hash), UpdatedAt: now, UpdatedBy: actor})
		return nil
	})
	h.cfg.SetAdminPasswordBcrypt(string(hash))
	// Invalidate all active sessions so anyone holding an old session must re-authenticate.
	h.sessions.DeleteAll()
	w.WriteHeader(http.StatusNoContent)
}

// ListCustomFeed handles GET /api/settings/custom-feed
func (h *SettingsHandler) ListCustomFeed(w http.ResponseWriter, r *http.Request) {
	var entries []db.CustomFeedEntry
	h.gdb.Order("added_at desc").Find(&entries)
	respondJSON(w, http.StatusOK, entries)
}

// AddCustomFeed handles POST /api/settings/custom-feed
func (h *SettingsHandler) AddCustomFeed(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Entry     string `json:"entry"`
		EntryType string `json:"entry_type"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Entry == "" {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "entry is required"})
		return
	}
	if req.EntryType != "domain" && req.EntryType != "url" {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "entry_type must be domain or url"})
		return
	}
	// Domain entries are used in a SQL LIKE suffix match; reject LIKE wildcards.
	if req.EntryType == "domain" && (strings.ContainsAny(req.Entry, "%_")) {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "domain entry must not contain wildcard characters"})
		return
	}
	entry := db.CustomFeedEntry{
		Entry:     strings.ToLower(strings.TrimSpace(req.Entry)),
		EntryType: req.EntryType,
		AddedAt:   time.Now(),
		AddedBy:   actorFromRequest(r),
	}
	if err := h.gdb.Write(func(tx *gorm.DB) error {
		return tx.Create(&entry).Error
	}); err != nil {
		respondJSON(w, http.StatusConflict, map[string]string{"error": "entry already exists"})
		return
	}
	respondJSON(w, http.StatusCreated, entry)
}

// DeleteCustomFeed handles DELETE /api/settings/custom-feed/{id}
func (h *SettingsHandler) DeleteCustomFeed(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimSuffix(r.URL.Path, "/"), "/")
	if len(parts) == 0 {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "id required"})
		return
	}
	idStr := parts[len(parts)-1]
	idVal, parseErr := strconv.ParseUint(idStr, 10, 64)
	if parseErr != nil || idVal == 0 {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	var result *gorm.DB
	if err := h.gdb.Write(func(tx *gorm.DB) error {
		result = tx.Delete(&db.CustomFeedEntry{}, idVal)
		return result.Error
	}); err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]string{"error": "db error"})
		return
	}
	if result == nil || result.RowsAffected == 0 {
		respondJSON(w, http.StatusNotFound, map[string]string{"error": "entry not found"})
		return
	}
	respondJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// TestAccount handles POST /api/settings/accounts/test
// Dials the IMAP server and attempts login to verify credentials without saving.
func (h *SettingsHandler) TestAccount(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Host          string `json:"host"`
		Port          int    `json:"port"`
		User          string `json:"user"`
		Pass          string `json:"pass"`
		TLSSkipVerify bool   `json:"tls_skip_verify"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Host == "" || req.User == "" || req.Pass == "" {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "host, user, and pass are required"})
		return
	}
	if req.Port == 0 {
		req.Port = 993
	}
	cfg := config.AccountConfig{Host: req.Host, Port: req.Port, User: req.User, Pass: req.Pass, TLSSkipVerify: req.TLSSkipVerify}
	if h.accountMgr == nil {
		respondJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "account manager unavailable"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	if err := h.accountMgr.Test(ctx, cfg); err != nil {
		respondJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

