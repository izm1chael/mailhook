package config

import (
	"os"
	"testing"
)

const validYAML = `
accounts:
  - name: primary
    host: imap.example.com
    port: 993
    user: test@example.com
    pass: secret
    mailbox: INBOX
    quarantine: Quarantine
`

func writeConfigFile(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp("", "mailhook-config-*.yaml")
	if err != nil {
		t.Fatalf("create temp config: %v", err)
	}
	f.WriteString(content) //nolint:errcheck
	f.Close()
	return f.Name()
}

func setupEnv(t *testing.T, cfgPath string) {
	t.Helper()
	os.Setenv("MAILHOOK_CONFIG", cfgPath)
	os.Setenv("MAILHOOK_ADMIN_PASSWORD_BCRYPT", "$2a$10$abcdefghijklmnopqrstuuVGmNlGTtWYYuHFCKGKP3gJLNPnELpmy") //nolint // nosemgrep: generic.secrets.security.detected-bcrypt-hash.detected-bcrypt-hash
	os.Setenv("MAILHOOK_DB_ENCRYPTION_KEY", "0000000000000000000000000000000000000000000000000000000000000000")
	os.Setenv("MAILHOOK_CSRF_SECRET", "test-csrf-secret-not-for-production")
	t.Cleanup(func() {
		os.Unsetenv("MAILHOOK_CONFIG")
		os.Unsetenv("MAILHOOK_ADMIN_PASSWORD_BCRYPT")
		os.Unsetenv("MAILHOOK_DB_ENCRYPTION_KEY")
		os.Unsetenv("MAILHOOK_CSRF_SECRET")
	})
}

func TestLoad_ValidConfig(t *testing.T) {
	cfgPath := writeConfigFile(t, validYAML)
	defer os.Remove(cfgPath)
	setupEnv(t, cfgPath)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Accounts) != 1 {
		t.Errorf("expected 1 account, got %d", len(cfg.Accounts))
	}
	if cfg.Accounts[0].Name != "primary" {
		t.Errorf("account name = %q, want primary", cfg.Accounts[0].Name)
	}
	if cfg.Accounts[0].Host != "imap.example.com" {
		t.Errorf("host = %q, want imap.example.com", cfg.Accounts[0].Host)
	}
}

func TestLoad_DefaultValues(t *testing.T) {
	cfgPath := writeConfigFile(t, validYAML)
	defer os.Remove(cfgPath)
	setupEnv(t, cfgPath)
	// Clear any existing env overrides
	os.Unsetenv("MAILHOOK_SPAM_SCORE")
	os.Unsetenv("MAILHOOK_REJECT_SCORE")
	os.Unsetenv("MAILHOOK_RETENTION_DAYS")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.SpamScore != 5.0 {
		t.Errorf("SpamScore = %.1f, want 5.0", cfg.SpamScore)
	}
	if cfg.RejectScore != 15.0 {
		t.Errorf("RejectScore = %.1f, want 15.0", cfg.RejectScore)
	}
	if cfg.RetentionDays != 30 {
		t.Errorf("RetentionDays = %d, want 30", cfg.RetentionDays)
	}
	if cfg.EMLQuarantineRetentionDays != 90 {
		t.Errorf("EMLQuarantineRetentionDays = %d, want 90", cfg.EMLQuarantineRetentionDays)
	}
	if cfg.EMLCleanRetain != false {
		t.Errorf("EMLCleanRetain should default to false")
	}
}

func TestLoad_EnvOverrides(t *testing.T) {
	cfgPath := writeConfigFile(t, validYAML)
	defer os.Remove(cfgPath)
	setupEnv(t, cfgPath)
	os.Setenv("MAILHOOK_SPAM_SCORE", "8.0")
	os.Setenv("MAILHOOK_REJECT_SCORE", "20.0")
	os.Setenv("MAILHOOK_EML_CLEAN_RETAIN", "true")
	t.Cleanup(func() {
		os.Unsetenv("MAILHOOK_SPAM_SCORE")
		os.Unsetenv("MAILHOOK_REJECT_SCORE")
		os.Unsetenv("MAILHOOK_EML_CLEAN_RETAIN")
	})

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.SpamScore != 8.0 {
		t.Errorf("SpamScore = %.1f, want 8.0", cfg.SpamScore)
	}
	if cfg.RejectScore != 20.0 {
		t.Errorf("RejectScore = %.1f, want 20.0", cfg.RejectScore)
	}
	if !cfg.EMLCleanRetain {
		t.Error("EMLCleanRetain should be true")
	}
}

func TestLoad_MissingPassword(t *testing.T) {
	cfgPath := writeConfigFile(t, validYAML)
	defer os.Remove(cfgPath)
	setupEnv(t, cfgPath)
	os.Unsetenv("MAILHOOK_ADMIN_PASSWORD_BCRYPT")

	_, err := Load()
	if err == nil {
		t.Error("expected error for missing admin password, got nil")
	}
}

func TestLoad_InvalidBcryptHash(t *testing.T) {
	cfgPath := writeConfigFile(t, validYAML)
	defer os.Remove(cfgPath)
	setupEnv(t, cfgPath)
	os.Setenv("MAILHOOK_ADMIN_PASSWORD_BCRYPT", "notabcrypt")
	t.Cleanup(func() { os.Unsetenv("MAILHOOK_ADMIN_PASSWORD_BCRYPT") })

	_, err := Load()
	if err == nil {
		t.Error("expected error for invalid bcrypt hash, got nil")
	}
}

// TestLoad_BcryptPlaceholderRejected verifies the shipped default placeholder is
// rejected at startup rather than silently accepted until the first login attempt.
func TestLoad_BcryptPlaceholderRejected(t *testing.T) {
	cfgPath := writeConfigFile(t, validYAML)
	defer os.Remove(cfgPath)
	setupEnv(t, cfgPath)
	os.Setenv("MAILHOOK_ADMIN_PASSWORD_BCRYPT", "$2b$12$changeme...") // nosemgrep: generic.secrets.security.detected-bcrypt-hash.detected-bcrypt-hash
	t.Cleanup(func() { os.Unsetenv("MAILHOOK_ADMIN_PASSWORD_BCRYPT") })

	_, err := Load()
	if err == nil {
		t.Error("expected error for placeholder bcrypt hash, got nil")
	}
}

func TestLoad_MissingDBEncryptionKey(t *testing.T) {
	cfgPath := writeConfigFile(t, validYAML)
	defer os.Remove(cfgPath)
	setupEnv(t, cfgPath)
	os.Unsetenv("MAILHOOK_DB_ENCRYPTION_KEY")

	_, err := Load()
	if err == nil {
		t.Error("expected error for missing MAILHOOK_DB_ENCRYPTION_KEY, got nil")
	}
}

func TestLoad_MissingCSRFSecret(t *testing.T) {
	cfgPath := writeConfigFile(t, validYAML)
	defer os.Remove(cfgPath)
	setupEnv(t, cfgPath)
	os.Unsetenv("MAILHOOK_CSRF_SECRET")

	_, err := Load()
	if err == nil {
		t.Error("expected error for missing MAILHOOK_CSRF_SECRET, got nil")
	}
}

func TestLoad_SpamScoreGtRejectScore(t *testing.T) {
	cfgPath := writeConfigFile(t, validYAML)
	defer os.Remove(cfgPath)
	setupEnv(t, cfgPath)
	os.Setenv("MAILHOOK_SPAM_SCORE", "20.0")
	os.Setenv("MAILHOOK_REJECT_SCORE", "5.0")
	t.Cleanup(func() {
		os.Unsetenv("MAILHOOK_SPAM_SCORE")
		os.Unsetenv("MAILHOOK_REJECT_SCORE")
	})

	_, err := Load()
	if err == nil {
		t.Error("expected validation error when spam_score >= reject_score")
	}
}

func TestLoad_NoAccounts(t *testing.T) {
	// An explicit config file with no accounts is valid — the daemon just won't
	// poll any IMAP mailboxes (useful for seed / UI-only deployments).
	cfgPath := writeConfigFile(t, "accounts: []\n")
	defer os.Remove(cfgPath)
	setupEnv(t, cfgPath)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error for empty accounts list: %v", err)
	}
	if len(cfg.Accounts) != 0 {
		t.Errorf("expected 0 accounts, got %d", len(cfg.Accounts))
	}
}

func TestLoad_DefaultPort(t *testing.T) {
	yaml := `
accounts:
  - name: primary
    host: imap.example.com
    user: test@example.com
    pass: secret
`
	cfgPath := writeConfigFile(t, yaml)
	defer os.Remove(cfgPath)
	setupEnv(t, cfgPath)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Accounts[0].Port != 993 {
		t.Errorf("default port = %d, want 993", cfg.Accounts[0].Port)
	}
	if cfg.Accounts[0].Mailbox != "INBOX" {
		t.Errorf("default mailbox = %q, want INBOX", cfg.Accounts[0].Mailbox)
	}
	if cfg.Accounts[0].Quarantine != "Quarantine" {
		t.Errorf("default quarantine = %q, want Quarantine", cfg.Accounts[0].Quarantine)
	}
}

func TestLoad_InvalidSpamScore(t *testing.T) {
	cfgPath := writeConfigFile(t, validYAML)
	defer os.Remove(cfgPath)
	setupEnv(t, cfgPath)
	os.Setenv("MAILHOOK_SPAM_SCORE", "notanumber")
	t.Cleanup(func() { os.Unsetenv("MAILHOOK_SPAM_SCORE") })

	_, err := Load()
	if err == nil {
		t.Error("expected error for invalid MAILHOOK_SPAM_SCORE, got nil")
	}
}

func TestLoad_InvalidRetentionDays(t *testing.T) {
	cfgPath := writeConfigFile(t, validYAML)
	defer os.Remove(cfgPath)
	setupEnv(t, cfgPath)
	os.Setenv("MAILHOOK_RETENTION_DAYS", "thirty")
	t.Cleanup(func() { os.Unsetenv("MAILHOOK_RETENTION_DAYS") })

	_, err := Load()
	if err == nil {
		t.Error("expected error for invalid MAILHOOK_RETENTION_DAYS, got nil")
	}
}

func TestLoad_InvalidScanTimeout(t *testing.T) {
	cfgPath := writeConfigFile(t, validYAML)
	defer os.Remove(cfgPath)
	setupEnv(t, cfgPath)
	os.Setenv("MAILHOOK_SCAN_TIMEOUT", "notaduration")
	t.Cleanup(func() { os.Unsetenv("MAILHOOK_SCAN_TIMEOUT") })

	_, err := Load()
	if err == nil {
		t.Error("expected error for invalid MAILHOOK_SCAN_TIMEOUT, got nil")
	}
}

func TestLoad_InvalidEMLCleanRetain(t *testing.T) {
	cfgPath := writeConfigFile(t, validYAML)
	defer os.Remove(cfgPath)
	setupEnv(t, cfgPath)
	os.Setenv("MAILHOOK_EML_CLEAN_RETAIN", "yes_please")
	t.Cleanup(func() { os.Unsetenv("MAILHOOK_EML_CLEAN_RETAIN") })

	_, err := Load()
	if err == nil {
		t.Error("expected error for invalid MAILHOOK_EML_CLEAN_RETAIN, got nil")
	}
}

func TestLoad_URLUnshortenDefaults(t *testing.T) {
	cfgPath := writeConfigFile(t, validYAML)
	defer os.Remove(cfgPath)
	setupEnv(t, cfgPath)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.URLUnshortenEnabled {
		t.Error("expected URLUnshortenEnabled=true by default")
	}
	if cfg.URLUnshortenMaxHops != 3 {
		t.Errorf("expected URLUnshortenMaxHops=3, got %d", cfg.URLUnshortenMaxHops)
	}
	if cfg.URLUnshortenPerURLTimeout.Seconds() != 5 {
		t.Errorf("expected URLUnshortenPerURLTimeout=5s, got %v", cfg.URLUnshortenPerURLTimeout)
	}
	if cfg.URLUnshortenRateLimit != 10 {
		t.Errorf("expected URLUnshortenRateLimit=10, got %d", cfg.URLUnshortenRateLimit)
	}
	if cfg.URLUnshortenRateBurst != 5 {
		t.Errorf("expected URLUnshortenRateBurst=5, got %d", cfg.URLUnshortenRateBurst)
	}
}

func TestLoad_NRDDefaults(t *testing.T) {
	cfgPath := writeConfigFile(t, validYAML)
	defer os.Remove(cfgPath)
	setupEnv(t, cfgPath)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.NRDEnabled {
		t.Error("expected NRDEnabled=true by default")
	}
	if cfg.NRDMaxAgeDays != 14 {
		t.Errorf("expected NRDMaxAgeDays=14, got %d", cfg.NRDMaxAgeDays)
	}
	if cfg.NRDCacheTTLHours != 24 {
		t.Errorf("expected NRDCacheTTLHours=24, got %d", cfg.NRDCacheTTLHours)
	}
	if cfg.NRDRDAPBaseURL != "https://rdap.org/domain/" {
		t.Errorf("expected NRDRDAPBaseURL default, got %q", cfg.NRDRDAPBaseURL)
	}
}

func TestLoad_URLUnshortenMaxHops_Override(t *testing.T) {
	cfgPath := writeConfigFile(t, validYAML)
	defer os.Remove(cfgPath)
	setupEnv(t, cfgPath)
	os.Setenv("MAILHOOK_URLUNSHORTEN_MAX_HOPS", "5")
	t.Cleanup(func() { os.Unsetenv("MAILHOOK_URLUNSHORTEN_MAX_HOPS") })

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.URLUnshortenMaxHops != 5 {
		t.Errorf("expected URLUnshortenMaxHops=5, got %d", cfg.URLUnshortenMaxHops)
	}
}

func TestLoad_URLUnshortenMaxHops_Invalid(t *testing.T) {
	cfgPath := writeConfigFile(t, validYAML)
	defer os.Remove(cfgPath)
	setupEnv(t, cfgPath)
	os.Setenv("MAILHOOK_URLUNSHORTEN_MAX_HOPS", "not-a-number")
	t.Cleanup(func() { os.Unsetenv("MAILHOOK_URLUNSHORTEN_MAX_HOPS") })

	_, err := Load()
	if err == nil {
		t.Error("expected error for invalid MAILHOOK_URLUNSHORTEN_MAX_HOPS, got nil")
	}
}

func TestLoad_NRDMaxAgeDays_Override(t *testing.T) {
	cfgPath := writeConfigFile(t, validYAML)
	defer os.Remove(cfgPath)
	setupEnv(t, cfgPath)
	os.Setenv("MAILHOOK_NRD_MAX_AGE_DAYS", "7")
	t.Cleanup(func() { os.Unsetenv("MAILHOOK_NRD_MAX_AGE_DAYS") })

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.NRDMaxAgeDays != 7 {
		t.Errorf("expected NRDMaxAgeDays=7, got %d", cfg.NRDMaxAgeDays)
	}
}

func TestLoad_URLUnshortenPerURLTimeout_Invalid(t *testing.T) {
	cfgPath := writeConfigFile(t, validYAML)
	defer os.Remove(cfgPath)
	setupEnv(t, cfgPath)
	os.Setenv("MAILHOOK_URLUNSHORTEN_PER_URL_TIMEOUT", "not-a-duration")
	t.Cleanup(func() { os.Unsetenv("MAILHOOK_URLUNSHORTEN_PER_URL_TIMEOUT") })

	_, err := Load()
	if err == nil {
		t.Error("expected error for invalid MAILHOOK_URLUNSHORTEN_PER_URL_TIMEOUT, got nil")
	}
}

func TestLoad_NRDEnabled_Override(t *testing.T) {
	cfgPath := writeConfigFile(t, validYAML)
	defer os.Remove(cfgPath)
	setupEnv(t, cfgPath)
	os.Setenv("MAILHOOK_NRD_ENABLED", "false")
	t.Cleanup(func() { os.Unsetenv("MAILHOOK_NRD_ENABLED") })

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.NRDEnabled {
		t.Error("expected NRDEnabled=false after override")
	}
}

func TestLoad_HTMLSmugglingDefaults(t *testing.T) {
	cfgPath := writeConfigFile(t, validYAML)
	defer os.Remove(cfgPath)
	setupEnv(t, cfgPath)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.HTMLSmugglingEnabled {
		t.Error("expected HTMLSmugglingEnabled=true by default")
	}
	if cfg.HTMLSmugglingMinB64KB != 10 {
		t.Errorf("expected HTMLSmugglingMinB64KB=10, got %d", cfg.HTMLSmugglingMinB64KB)
	}
	if !cfg.HiddenTextEnabled {
		t.Error("expected HiddenTextEnabled=true by default")
	}
}

func TestLoad_HTMLSmugglingEnabled_Override(t *testing.T) {
	cfgPath := writeConfigFile(t, validYAML)
	defer os.Remove(cfgPath)
	setupEnv(t, cfgPath)
	os.Setenv("MAILHOOK_HTML_SMUGGLING_ENABLED", "false")
	t.Cleanup(func() { os.Unsetenv("MAILHOOK_HTML_SMUGGLING_ENABLED") })

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.HTMLSmugglingEnabled {
		t.Error("expected HTMLSmugglingEnabled=false after override")
	}
}

func TestLoad_HTMLSmugglingMinB64KB_Override(t *testing.T) {
	cfgPath := writeConfigFile(t, validYAML)
	defer os.Remove(cfgPath)
	setupEnv(t, cfgPath)
	os.Setenv("MAILHOOK_HTML_SMUGGLING_MIN_B64_KB", "25")
	t.Cleanup(func() { os.Unsetenv("MAILHOOK_HTML_SMUGGLING_MIN_B64_KB") })

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.HTMLSmugglingMinB64KB != 25 {
		t.Errorf("expected HTMLSmugglingMinB64KB=25, got %d", cfg.HTMLSmugglingMinB64KB)
	}
}

func TestLoad_HTMLSmugglingMinB64KB_Invalid(t *testing.T) {
	cfgPath := writeConfigFile(t, validYAML)
	defer os.Remove(cfgPath)
	setupEnv(t, cfgPath)
	os.Setenv("MAILHOOK_HTML_SMUGGLING_MIN_B64_KB", "notanumber")
	t.Cleanup(func() { os.Unsetenv("MAILHOOK_HTML_SMUGGLING_MIN_B64_KB") })

	_, err := Load()
	if err == nil {
		t.Error("expected error for invalid MAILHOOK_HTML_SMUGGLING_MIN_B64_KB, got nil")
	}
}

func TestLoad_HiddenTextEnabled_Override(t *testing.T) {
	cfgPath := writeConfigFile(t, validYAML)
	defer os.Remove(cfgPath)
	setupEnv(t, cfgPath)
	os.Setenv("MAILHOOK_HIDDEN_TEXT_ENABLED", "false")
	t.Cleanup(func() { os.Unsetenv("MAILHOOK_HIDDEN_TEXT_ENABLED") })

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.HiddenTextEnabled {
		t.Error("expected HiddenTextEnabled=false after override")
	}
}

func TestLoad_CSRFChangemePrefixRejected(t *testing.T) {
	cfgPath := writeConfigFile(t, validYAML)
	defer os.Remove(cfgPath)
	setupEnv(t, cfgPath)
	os.Setenv("MAILHOOK_CSRF_SECRET", "changeme-generate-with-openssl-rand-hex-32")
	t.Cleanup(func() { os.Unsetenv("MAILHOOK_CSRF_SECRET") })

	_, err := Load()
	if err == nil {
		t.Error("expected error for changeme CSRF secret, got nil")
	}
}

func TestLoad_CSRFTooShortRejected(t *testing.T) {
	cfgPath := writeConfigFile(t, validYAML)
	defer os.Remove(cfgPath)
	setupEnv(t, cfgPath)
	os.Setenv("MAILHOOK_CSRF_SECRET", "tooshort")
	t.Cleanup(func() { os.Unsetenv("MAILHOOK_CSRF_SECRET") })

	_, err := Load()
	if err == nil {
		t.Error("expected error for short CSRF secret, got nil")
	}
}

func TestLoad_DBKeyChangemePrefixRejected(t *testing.T) {
	cfgPath := writeConfigFile(t, validYAML)
	defer os.Remove(cfgPath)
	setupEnv(t, cfgPath)
	os.Setenv("MAILHOOK_DB_ENCRYPTION_KEY", "changeme-generate-with-openssl-rand-hex-32")
	t.Cleanup(func() { os.Unsetenv("MAILHOOK_DB_ENCRYPTION_KEY") })

	_, err := Load()
	if err == nil {
		t.Error("expected error for changeme DB encryption key, got nil")
	}
}
