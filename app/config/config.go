package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

// AccountConfig holds the IMAP credentials and folder settings for one mailbox.
type AccountConfig struct {
	Name          string `yaml:"name"`
	Host          string `yaml:"host"`
	Port          int    `yaml:"port"`
	User          string `yaml:"user"`
	Pass          string `yaml:"pass"`
	Mailbox       string `yaml:"mailbox"`
	Quarantine    string `yaml:"quarantine"`
	TLSSkipVerify bool   `yaml:"tls_skip_verify"`
}

// Config is the complete runtime configuration for MailHook.
// Global settings are read from environment variables.
// Per-account IMAP settings are read from the YAML config file.
type Config struct {
	mu sync.RWMutex //nolint:govet // protects fields mutated by settings handlers at runtime

	// Loaded from YAML config file
	Accounts []AccountConfig

	// Scanners
	RspamdURL    string
	ClamAVAddr   string
	YARARulesDir string
	VTAPIKey     string
	AbuseIPDBKey string

	// Verdict thresholds
	SpamScore   float64
	RejectScore float64

	// Web
	ListenAddr          string
	AdminUser           string
	AdminPasswordBcrypt string
	MetricsAllowedCIDRs []string

	// Storage
	DataDir                    string
	FeedsCacheDir              string
	DBPath                     string
	RetentionDays              int
	EMLCleanRetain             bool // store EMLs for clean mail
	EMLQuarantineRetentionDays int  // longer retention for quarantined items

	// Notifications
	NtfyURL   string
	NtfyTopic string
	NtfyToken string

	// Timing
	ScanTimeout         time.Duration
	FeedRefreshInterval time.Duration
	IMAPReconnectMax    time.Duration

	// Concurrency
	MaxConcurrentScans int

	// Security
	TrustedProxies   []string // CIDRs whose X-Forwarded-For headers are honoured
	CSRFSecret       string   // HMAC key for signing CSRF tokens (MAILHOOK_CSRF_SECRET)
	InsecureCookies  bool     // disable Secure flag on cookies (dev/HTTP-only environments)
	DBEncryptionKey  string   // hex-encoded 32-byte AES-256 key for at-rest credential encryption
	RedactWebhookPII bool     // mask From/Subject in ntfy and webhook payloads

	// Limits
	MaxEmailSizeMB int // total attachment bytes per email before truncation (0 = unlimited)

	// Logging
	LogLevel  string
	LogFormat string

	// URL Unshortening
	URLUnshortenEnabled       bool
	URLUnshortenMaxHops       int
	URLUnshortenPerURLTimeout time.Duration
	URLUnshortenRateLimit     int // requests/second
	URLUnshortenRateBurst     int // token bucket burst size

	// NRD Detection
	NRDEnabled       bool
	NRDMaxAgeDays    int
	NRDCacheTTLHours int
	NRDRDAPBaseURL   string

	// VirusTotal cache TTL
	VTCacheTTLHours         int // positive result cache TTL, default 24h
	VTNotFoundCacheTTLHours int // 0/0 not-found result cache TTL, default 4h

	// HTML Smuggling Detection
	HTMLSmugglingEnabled  bool
	HTMLSmugglingMinB64KB int // minimum base64 blob size (KB) to flag

	// Hidden Text / ZeroFont Detection
	HiddenTextEnabled bool

	// ONNX AI scanner (only active with -tags ai)
	ONNXModelsDir     string
	ONNXBERTThreshold float64
	ONNXDGAThreshold  float64

	// Email authentication
	// TrustedAuthservID is the authserv-id whose Authentication-Results headers
	// are trusted. If empty, all Authentication-Results headers are accepted
	// (backwards-compatible default; recommended to set in production).
	TrustedAuthservID string
}

// yamlFile is the on-disk structure of config.yaml.
type yamlFile struct {
	Accounts []struct {
		Name          string `yaml:"name"`
		Host          string `yaml:"host"`
		Port          int    `yaml:"port"`
		User          string `yaml:"user"`
		Pass          string `yaml:"pass"`
		Mailbox       string `yaml:"mailbox"`
		Quarantine    string `yaml:"quarantine"`
		TLSSkipVerify bool   `yaml:"tls_skip_verify"`
	} `yaml:"accounts"`
}

// Load reads configuration from the YAML file (path from MAILHOOK_CONFIG env var,
// default ./config.yaml) and environment variables. Env vars take precedence over
// YAML defaults for global settings. Returns an error if required fields are missing
// or validation fails.
func Load() (*Config, error) {
	cfg := &Config{
		RspamdURL:           getEnv("MAILHOOK_RSPAMD_URL", "http://rspamd:11333"),
		ClamAVAddr:          getEnv("MAILHOOK_CLAMAV_ADDR", "clamav:3310"),
		YARARulesDir:        getEnv("MAILHOOK_YARA_RULES_DIR", "/rules"),
		VTAPIKey:            getEnv("MAILHOOK_VT_API_KEY", ""),
		AbuseIPDBKey:        getEnv("MAILHOOK_ABUSEIPDB_KEY", ""),
		ListenAddr:          getEnv("MAILHOOK_LISTEN", "0.0.0.0:8080"),
		AdminUser:           getEnv("MAILHOOK_ADMIN_USER", "admin"),
		AdminPasswordBcrypt: getEnv("MAILHOOK_ADMIN_PASSWORD_BCRYPT", ""),
		DataDir:             getEnv("MAILHOOK_DATA_DIR", "/data"),
		FeedsCacheDir:       getEnv("MAILHOOK_FEEDS_CACHE_DIR", "/feeds-cache"),
		DBPath:              getEnv("MAILHOOK_DB_PATH", "/data/mailhook.db"),
		NtfyURL:             getEnv("MAILHOOK_NTFY_URL", ""),
		NtfyTopic:           getEnv("MAILHOOK_NTFY_TOPIC", "mailhook"),
		NtfyToken:           getEnv("MAILHOOK_NTFY_TOKEN", ""),
		LogLevel:            getEnv("MAILHOOK_LOG_LEVEL", "info"),
		LogFormat:           getEnv("MAILHOOK_LOG_FORMAT", "json"),
	}

	var parseErr error
	if cfg.SpamScore, parseErr = getEnvFloat("MAILHOOK_SPAM_SCORE", 5.0); parseErr != nil {
		return nil, parseErr
	}
	if cfg.RejectScore, parseErr = getEnvFloat("MAILHOOK_REJECT_SCORE", 15.0); parseErr != nil {
		return nil, parseErr
	}
	if cfg.RetentionDays, parseErr = getEnvInt("MAILHOOK_RETENTION_DAYS", 30); parseErr != nil {
		return nil, parseErr
	}
	if cfg.EMLCleanRetain, parseErr = getEnvBool("MAILHOOK_EML_CLEAN_RETAIN", false); parseErr != nil {
		return nil, parseErr
	}
	if cfg.EMLQuarantineRetentionDays, parseErr = getEnvInt("MAILHOOK_EML_QUARANTINE_RETENTION_DAYS", 90); parseErr != nil {
		return nil, parseErr
	}
	if cfg.ScanTimeout, parseErr = getEnvDuration("MAILHOOK_SCAN_TIMEOUT", 60*time.Second); parseErr != nil {
		return nil, parseErr
	}
	if cfg.FeedRefreshInterval, parseErr = getEnvDuration("MAILHOOK_FEED_REFRESH_INTERVAL", 6*time.Hour); parseErr != nil {
		return nil, parseErr
	}
	if cfg.IMAPReconnectMax, parseErr = getEnvDuration("MAILHOOK_IMAP_RECONNECT_MAX", 5*time.Minute); parseErr != nil {
		return nil, parseErr
	}
	if cfg.MaxConcurrentScans, parseErr = getEnvInt("MAILHOOK_MAX_CONCURRENT_SCANS", 20); parseErr != nil {
		return nil, parseErr
	}
	if cfg.MaxEmailSizeMB, parseErr = getEnvInt("MAILHOOK_MAX_EMAIL_SIZE_MB", 100); parseErr != nil {
		return nil, parseErr
	}
	if cfg.InsecureCookies, parseErr = getEnvBool("MAILHOOK_INSECURE_COOKIES", false); parseErr != nil {
		return nil, parseErr
	}
	if cfg.RedactWebhookPII, parseErr = getEnvBool("MAILHOOK_REDACT_WEBHOOK_PII", true); parseErr != nil {
		return nil, parseErr
	}
	cfg.DBEncryptionKey = getEnv("MAILHOOK_DB_ENCRYPTION_KEY", "")

	if cfg.URLUnshortenEnabled, parseErr = getEnvBool("MAILHOOK_URLUNSHORTEN_ENABLED", true); parseErr != nil {
		return nil, parseErr
	}
	if cfg.URLUnshortenMaxHops, parseErr = getEnvInt("MAILHOOK_URLUNSHORTEN_MAX_HOPS", 3); parseErr != nil {
		return nil, parseErr
	}
	if cfg.URLUnshortenPerURLTimeout, parseErr = getEnvDuration("MAILHOOK_URLUNSHORTEN_PER_URL_TIMEOUT", 5*time.Second); parseErr != nil {
		return nil, parseErr
	}
	if cfg.URLUnshortenRateLimit, parseErr = getEnvInt("MAILHOOK_URLUNSHORTEN_RATE_LIMIT", 10); parseErr != nil {
		return nil, parseErr
	}
	if cfg.URLUnshortenRateBurst, parseErr = getEnvInt("MAILHOOK_URLUNSHORTEN_RATE_BURST", 5); parseErr != nil {
		return nil, parseErr
	}
	if cfg.NRDEnabled, parseErr = getEnvBool("MAILHOOK_NRD_ENABLED", true); parseErr != nil {
		return nil, parseErr
	}
	if cfg.NRDMaxAgeDays, parseErr = getEnvInt("MAILHOOK_NRD_MAX_AGE_DAYS", 14); parseErr != nil {
		return nil, parseErr
	}
	if cfg.NRDCacheTTLHours, parseErr = getEnvInt("MAILHOOK_NRD_CACHE_TTL_HOURS", 24); parseErr != nil {
		return nil, parseErr
	}
	cfg.NRDRDAPBaseURL = getEnv("MAILHOOK_NRD_RDAP_BASE_URL", "https://rdap.org/domain/")

	if cfg.VTCacheTTLHours, parseErr = getEnvInt("MAILHOOK_VT_CACHE_TTL_HOURS", 24); parseErr != nil {
		return nil, parseErr
	}
	if cfg.VTNotFoundCacheTTLHours, parseErr = getEnvInt("MAILHOOK_VT_NOTFOUND_CACHE_TTL_HOURS", 4); parseErr != nil {
		return nil, parseErr
	}

	if cfg.HTMLSmugglingEnabled, parseErr = getEnvBool("MAILHOOK_HTML_SMUGGLING_ENABLED", true); parseErr != nil {
		return nil, parseErr
	}
	if cfg.HTMLSmugglingMinB64KB, parseErr = getEnvInt("MAILHOOK_HTML_SMUGGLING_MIN_B64_KB", 10); parseErr != nil {
		return nil, parseErr
	}
	if cfg.HiddenTextEnabled, parseErr = getEnvBool("MAILHOOK_HIDDEN_TEXT_ENABLED", true); parseErr != nil {
		return nil, parseErr
	}

	cfg.ONNXModelsDir = getEnv("MAILHOOK_ONNX_MODELS_DIR", "")
	if cfg.ONNXBERTThreshold, parseErr = getEnvFloat("MAILHOOK_ONNX_BERT_THRESHOLD", 0.92); parseErr != nil {
		return nil, parseErr
	}
	if cfg.ONNXDGAThreshold, parseErr = getEnvFloat("MAILHOOK_ONNX_DGA_THRESHOLD", 0.80); parseErr != nil {
		return nil, parseErr
	}

	// Default to loopback only — operators must explicitly opt in to wider ranges.
	// These endpoints (/metrics, /api/scan) are unauthenticated and must not be
	// proxied to untrusted clients.
	rawCIDRs := getEnv("MAILHOOK_METRICS_ALLOWED_CIDRS", "127.0.0.1/32,::1/128")
	for _, cidr := range strings.Split(rawCIDRs, ",") {
		if cidr = strings.TrimSpace(cidr); cidr != "" {
			cfg.MetricsAllowedCIDRs = append(cfg.MetricsAllowedCIDRs, cidr)
		}
	}

	rawProxies := getEnv("MAILHOOK_TRUSTED_PROXIES", "")
	for _, cidr := range strings.Split(rawProxies, ",") {
		if cidr = strings.TrimSpace(cidr); cidr != "" {
			cfg.TrustedProxies = append(cfg.TrustedProxies, cidr)
		}
	}

	cfg.CSRFSecret = getEnv("MAILHOOK_CSRF_SECRET", "")
	cfg.TrustedAuthservID = getEnv("MAILHOOK_TRUSTED_AUTHSERV_ID", "")

	// Load accounts from YAML config file.
	// If MAILHOOK_CONFIG is not set and the default config.yaml is absent, skip
	// gracefully — env-only deployments with no IMAP accounts are valid.
	cfgPath, cfgExplicit := os.LookupEnv("MAILHOOK_CONFIG")
	if !cfgExplicit {
		cfgPath = "config.yaml"
	}
	if err := cfg.loadYAML(cfgPath); err != nil {
		if !cfgExplicit && errors.Is(err, os.ErrNotExist) {
			// Default path absent: run without IMAP accounts.
		} else {
			return nil, fmt.Errorf("config file: %w", err)
		}
	}

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("config validation: %w", err)
	}

	return cfg, nil
}

func (c *Config) loadYAML(path string) error {
	f, err := os.Open(path) // #nosec G304 -- path is the operator-provided config file path, not request input
	if err != nil {
		return err // preserve os.ErrNotExist for caller to inspect
	}
	defer f.Close()

	var yf yamlFile
	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	if err := dec.Decode(&yf); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}

	for i, a := range yf.Accounts {
		ac := AccountConfig{
			Name:          a.Name,
			Host:          a.Host,
			Port:          a.Port,
			User:          a.User,
			Pass:          a.Pass,
			Mailbox:       a.Mailbox,
			Quarantine:    a.Quarantine,
			TLSSkipVerify: a.TLSSkipVerify,
		}
		if ac.Port == 0 {
			ac.Port = 993
		}
		if ac.Mailbox == "" {
			ac.Mailbox = "INBOX"
		}
		if ac.Quarantine == "" {
			ac.Quarantine = "Quarantine"
		}
		if ac.Name == "" {
			ac.Name = fmt.Sprintf("account%d", i+1)
		}
		c.Accounts = append(c.Accounts, ac)
	}

	return nil
}

func (c *Config) validate() error {
	seen := make(map[string]bool)
	for i, a := range c.Accounts {
		if a.Host == "" {
			return fmt.Errorf("accounts[%d].host is required", i)
		}
		if a.User == "" {
			return fmt.Errorf("accounts[%d].user is required", i)
		}
		if a.Pass == "" {
			return fmt.Errorf("accounts[%d].pass is required", i)
		}
		if seen[a.Name] {
			return fmt.Errorf("duplicate account name %q", a.Name)
		}
		seen[a.Name] = true
	}

	if c.AdminPasswordBcrypt == "" {
		return fmt.Errorf("MAILHOOK_ADMIN_PASSWORD_BCRYPT is required")
	}
	if _, err := bcrypt.Cost([]byte(c.AdminPasswordBcrypt)); err != nil {
		return fmt.Errorf("MAILHOOK_ADMIN_PASSWORD_BCRYPT is not a valid bcrypt hash: %w", err)
	}

	if c.SpamScore >= c.RejectScore {
		return fmt.Errorf("MAILHOOK_SPAM_SCORE (%.1f) must be less than MAILHOOK_REJECT_SCORE (%.1f)",
			c.SpamScore, c.RejectScore)
	}

	if c.NtfyURL != "" {
		if _, err := url.ParseRequestURI(c.NtfyURL); err != nil {
			return fmt.Errorf("MAILHOOK_NTFY_URL is not a valid URL: %w", err)
		}
	}

	if c.DBEncryptionKey == "" {
		return fmt.Errorf("MAILHOOK_DB_ENCRYPTION_KEY is required; generate with: openssl rand -hex 32")
	}
	if c.DBEncryptionKey == "REPLACE_WITH_HEX_KEY" || strings.HasPrefix(c.DBEncryptionKey, "changeme") {
		return fmt.Errorf("MAILHOOK_DB_ENCRYPTION_KEY is still set to a placeholder — replace it before running")
	}

	if c.CSRFSecret == "" {
		return fmt.Errorf("MAILHOOK_CSRF_SECRET is required; generate with: openssl rand -hex 32")
	}
	if c.CSRFSecret == "REPLACE_WITH_HEX_SECRET" || strings.HasPrefix(c.CSRFSecret, "changeme") {
		return fmt.Errorf("MAILHOOK_CSRF_SECRET is still set to a placeholder — replace it before running")
	}
	if len(c.CSRFSecret) < 32 {
		return fmt.Errorf("MAILHOOK_CSRF_SECRET must be at least 32 characters; generate with: openssl rand -hex 32")
	}

	return nil
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getEnvFloat(key string, def float64) (float64, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return 0, fmt.Errorf("env %s=%q: %w", key, v, err)
	}
	return f, nil
}

func getEnvInt(key string, def int) (int, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	i, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("env %s=%q: %w", key, v, err)
	}
	return i, nil
}

func getEnvBool(key string, def bool) (bool, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, fmt.Errorf("env %s=%q: %w", key, v, err)
	}
	return b, nil
}

func getEnvDuration(key string, def time.Duration) (time.Duration, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("env %s=%q: %w", key, v, err)
	}
	return d, nil
}

// Thread-safe accessors for fields mutated at runtime by settings handlers.
// These fields are read by pipeline goroutines and auth handlers concurrently.

func (c *Config) GetSpamScore() float64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.SpamScore
}

func (c *Config) SetSpamScore(v float64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.SpamScore = v
}

func (c *Config) GetRejectScore() float64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.RejectScore
}

func (c *Config) SetRejectScore(v float64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.RejectScore = v
}

func (c *Config) GetAdminPasswordBcrypt() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.AdminPasswordBcrypt
}

func (c *Config) SetAdminPasswordBcrypt(v string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.AdminPasswordBcrypt = v
}
