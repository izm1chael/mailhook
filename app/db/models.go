package db

import (
	"fmt"
	"time"

	"gorm.io/datatypes"
)

// Scan is the primary record created for every email processed by the pipeline.
// Scanner results are stored as JSON columns to avoid a complex join schema.
type Scan struct {
	ID        uint      `gorm:"primaryKey"`
	CreatedAt time.Time `gorm:"index"`
	UpdatedAt time.Time

	// IMAP context
	AccountName  string `gorm:"index;not null"` // which account this arrived on
	IMAPMailbox  string
	IMAPUID      uint32 `gorm:"uniqueIndex:idx_account_uid,priority:2"`
	AccountUID   string `gorm:"uniqueIndex:idx_account_uid,priority:1"` // AccountName+":"+IMAPMailbox+":"+IMAPUID

	// Message identity
	MessageID string
	Subject   string
	From      string
	To        string // comma-separated if multiple
	Date      time.Time
	SizeBytes int64
	EMLPath   string // relative path under DataDir/emls/

	// Authentication headers
	SPFResult  string
	DKIMResult string
	DMARCResult string
	SendingIP  string

	// Rspamd
	RspamdScore   float64
	RspamdAction  string
	RspamdSymbols datatypes.JSON // []RspamdSymbol

	// ClamAV
	ClamAVStatus string // CLEAN | VIRUS:<name> | ERROR | TIMEOUT | UNAVAILABLE

	// YARA
	YARAMatches datatypes.JSON // []string

	// URL reputation
	URLHits         datatypes.JSON // []URLHit
	ResolvedURLHits datatypes.JSON // []ResolvedURLHit

	// Attachments
	AttachmentCount int
	Attachments     datatypes.JSON // []AttachmentInfo

	// IP reputation (optional)
	IPReputation datatypes.JSON // *IPReputationResult or null

	// VirusTotal (optional)
	VTResults datatypes.JSON // []VTResult

	// MalwareBazaar (optional)
	MBResults datatypes.JSON // []MBResult

	// NRD detection (optional)
	NRDHits datatypes.JSON // []NRDHit

	// HTML smuggling detection (optional)
	HTMLSmugglingHits datatypes.JSON // []HTMLSmugglingHit

	// Hidden text / zero-font detection (optional)
	HiddenTextHits datatypes.JSON // []HiddenTextHit

	// Full URL list for retrospective re-checking against updated threat feeds.
	ScannedURLs datatypes.JSON // []string

	// Verdict
	Verdict       string  // CLEAN | SPAM | PHISH | MALWARE | SUSPICIOUS
	VerdictReason string
	Confidence    float64 // 0.0–1.0

	// Lifecycle
	Status     string `gorm:"index"` // INBOX | QUARANTINED | RELEASED | DELETED | LEARNED_HAM | LEARNED_SPAM
	ActionedBy string // "auto" or "user:<username>"
	ActionedAt *time.Time

	// Origin
	Source string `gorm:"index"` // "" (live) | "backfill"
}

// MakeAccountUID builds the globally-unique dedup key for a message.
// IMAP UIDs are only unique within a (mailbox, UIDVALIDITY), so the mailbox
// MUST be included — otherwise INBOX UID 1 and Quarantine UID 1 collide (F-056).
func MakeAccountUID(account, mailbox string, uid uint32) string {
	return fmt.Sprintf("%s:%s:%d", account, mailbox, uid)
}

// RspamdSymbol is stored inside Scan.RspamdSymbols as JSON.
type RspamdSymbol struct {
	Name        string  `json:"name"`
	Score       float64 `json:"score"`
	Description string  `json:"description,omitempty"`
}

// URLHit is stored inside Scan.URLHits as JSON.
type URLHit struct {
	URL        string `json:"url"`
	Domain     string `json:"domain"`
	Feed       string `json:"feed"`        // urlhaus | phishtank | openphish
	ThreatType string `json:"threat_type"` // malware | phishing
}

// ResolvedURLHit is stored inside Scan.ResolvedURLHits as JSON.
// It records the result of following HTTP redirects for a URL found in the email.
type ResolvedURLHit struct {
	OriginalURL string `json:"original_url"`
	ResolvedURL string `json:"resolved_url"`
	Hops        int    `json:"hops"`
	Feed        string `json:"feed,omitempty"`
	ThreatType  string `json:"threat_type,omitempty"`
	Blocked     bool   `json:"blocked,omitempty"` // true if redirect chain hit a private IP (SSRF guard)
}

// NRDHit is stored inside Scan.NRDHits as JSON.
// It records a domain (From: or URL) found to be newly registered.
type NRDHit struct {
	Domain           string `json:"domain"`
	RegistrationDate string `json:"registration_date"` // ISO8601
	AgeDays          int    `json:"age_days"`
	Source           string `json:"source"` // "from" | "url"
}

// HTMLSmugglingHit is stored inside Scan.HTMLSmugglingHits as JSON.
// It records a source (HTML attachment or body) where smuggling indicators were found.
type HTMLSmugglingHit struct {
	Source    string   `json:"source"`      // "body" or "attachment:<filename>"
	BlobAPIs  []string `json:"blob_apis"`   // matched Blob API names
	B64SizeKB int      `json:"b64_size_kb"` // largest base64 chunk converted to KB
}

// HiddenTextHit is stored inside Scan.HiddenTextHits as JSON.
// It records a CSS hiding technique found in the HTML body.
type HiddenTextHit struct {
	Technique string `json:"technique"` // zero_font | display_none | visibility_hidden | opacity_zero | color_match
	Count     int    `json:"count"`     // number of matching elements
	Sample    string `json:"sample"`    // first 80 chars of matching text content
}

// AttachmentInfo is stored inside Scan.Attachments as JSON.
type AttachmentInfo struct {
	Filename     string   `json:"filename"`
	ContentType  string   `json:"content_type"`
	SizeBytes    int64    `json:"size_bytes"`
	SHA256       string   `json:"sha256"`
	Extension    string   `json:"extension"`
	IsDangerous  bool     `json:"is_dangerous"`
	ClamAVResult string   `json:"clamav_result,omitempty"`
	YARAMatches  []string `json:"yara_matches,omitempty"`
	VTPositives  int      `json:"vt_positives,omitempty"`
	VTTotal      int      `json:"vt_total,omitempty"`
	MBSignature  string   `json:"mb_signature,omitempty"` // non-empty if MalwareBazaar matched
}

// IPReputationResult is stored inside Scan.IPReputation as JSON.
type IPReputationResult struct {
	IP          string `json:"ip"`
	AbuseScore  int    `json:"abuse_score"`
	TotalReports int   `json:"total_reports"`
	CountryCode string `json:"country_code,omitempty"`
	ISP         string `json:"isp,omitempty"`
	Source      string `json:"source"` // api | cache | unavailable
}

// VTResult is stored inside Scan.VTResults as JSON.
type VTResult struct {
	SHA256    string `json:"sha256"`
	Filename  string `json:"filename,omitempty"`
	Positives int    `json:"positives"`
	Total     int    `json:"total"`
	Permalink string `json:"permalink,omitempty"`
	Source    string `json:"source"` // api | cache | unavailable
}

// MBResult is stored inside Scan.MBResults as JSON.
type MBResult struct {
	SHA256    string `json:"sha256"`
	Filename  string `json:"filename,omitempty"`
	Signature string `json:"signature,omitempty"` // AV family label from feed
	Source    string `json:"source"`              // "feed"
}

// IPReputationCache stores AbuseIPDB results to avoid redundant API calls.
type IPReputationCache struct {
	IP           string    `gorm:"primaryKey"`
	AbuseScore   int
	TotalReports int
	CountryCode  string
	ISP          string
	FetchedAt    time.Time
	ExpiresAt    time.Time `gorm:"index"`
}

// NRDCache stores RDAP domain registration lookup results to avoid redundant external calls.
type NRDCache struct {
	Domain           string    `gorm:"primaryKey"`
	RegistrationDate time.Time // zero if RDAP returned no registration event
	LookupSuccess    bool      // false = RDAP 404 or returned no date
	FetchedAt        time.Time
	ExpiresAt        time.Time `gorm:"index"`
}

// VTHashCache stores VirusTotal hash lookup results.
type VTHashCache struct {
	SHA256    string    `gorm:"primaryKey"`
	Positives int
	Total     int
	FetchedAt time.Time
}

// MalwareBazaarHash stores hashes from the MalwareBazaar feed.
type MalwareBazaarHash struct {
	SHA256    string    `gorm:"primaryKey"`
	Signature string    // AV family / malware name (may be empty)
	FileType  string    // e.g. "exe", "dll", "doc"
	Tags      string    // raw comma-separated tags from CSV
	AddedAt   time.Time // upload timestamp from feed
	SeenAt    time.Time // when this row was first inserted locally
}

// FeedMeta records the last refresh time and size of each threat feed.
type FeedMeta struct {
	Name          string    `gorm:"primaryKey"`
	LastRefreshed time.Time
	EntryCount    int
	LoadedAt      time.Time
}

// Session persists authenticated web sessions across restarts.
type Session struct {
	ID        uint      `gorm:"primaryKey"`
	Token     string    `gorm:"uniqueIndex;not null"`
	Username  string    `gorm:"not null"`
	IPAddr    string
	CreatedAt time.Time
	ExpiresAt time.Time `gorm:"index"`
}

// AuditLog records every action taken on a scan (quarantine, release, delete, learn).
type AuditLog struct {
	ID        uint      `gorm:"primaryKey"`
	ScanID    uint      `gorm:"index;not null"`
	Action    string    `gorm:"not null"` // QUARANTINE | RELEASE | DELETE | LEARN_HAM | LEARN_SPAM | RESCAN
	Actor     string    `gorm:"not null"` // "auto" or "user:<name>"
	Note      string
	CreatedAt time.Time `gorm:"index"`
}

// Whitelist entries cause matching emails to bypass or scan-and-release.
// Entry is a full address (user@domain.com) or domain prefix (@domain.com).
type Whitelist struct {
	ID          uint      `gorm:"primaryKey"`
	Entry       string    `gorm:"uniqueIndex;not null"`
	EntryType   string    `gorm:"not null"` // "address" | "domain"
	BypassScan  bool      // true = skip all scanning; false = scan but force INBOX
	AddedAt     time.Time
	AddedReason string
}

// Blocklist entries trigger immediate quarantine without scanning.
// Entry is a full address or domain prefix.
type Blocklist struct {
	ID          uint      `gorm:"primaryKey"`
	Entry       string    `gorm:"uniqueIndex;not null"`
	EntryType   string    `gorm:"not null"` // "address" | "domain"
	AddedAt     time.Time
	AddedReason string
}

// DailyStat aggregates per-day verdict counts for the stats page and health endpoint.
type DailyStat struct {
	Date        string `gorm:"primaryKey"` // YYYY-MM-DD
	Total       int
	Clean       int
	Spam        int
	Phish       int
	Malware     int
	Suspicious  int
	Released    int
	Deleted     int
	LearnedHam  int
	LearnedSpam int
}

// Account stores IMAP account configuration. Accounts from config.yaml are upserted
// at startup so the DB is always the live source of truth.
//
// Pass is encrypted at rest using AES-256-GCM when MAILHOOK_DB_ENCRYPTION_KEY is set.
// Legacy plaintext rows are read transparently and re-encrypted on next write.
type Account struct {
	Name          string          `gorm:"primaryKey"`
	Host          string          `gorm:"not null"`
	Port          int             `gorm:"not null"`
	User          string          `gorm:"not null"`
	Pass          EncryptedString `gorm:"not null"`
	Mailbox       string    `gorm:"not null;default:INBOX"`
	Quarantine    string    `gorm:"not null;default:Quarantine"`
	TLSSkipVerify bool      `gorm:"default:false"`
	BackfillDays  int       `gorm:"default:0"` // 0 = disabled, N = last N days, -1 = all time
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// SchemaVersion tracks applied migrations so AutoMigrate is not the only guard.
type SchemaVersion struct {
	Version   int       `gorm:"primaryKey"`
	AppliedAt time.Time
	Note      string
}

// CustomFeedEntry stores user-defined domain or URL threat indicators.
type CustomFeedEntry struct {
	ID        uint      `gorm:"primaryKey"`
	Entry     string    `gorm:"uniqueIndex"`
	EntryType string    // "domain" | "url"
	AddedAt   time.Time
	AddedBy   string
}

// AppSetting persists runtime-tunable configuration values (e.g. thresholds).
type AppSetting struct {
	Key       string    `gorm:"primaryKey"`
	Value     string    `gorm:"not null"`
	UpdatedAt time.Time
	UpdatedBy string
}

// Source constants for Scan.Source.
const (
	SourceLive     = ""         // normal live processing
	SourceBackfill = "backfill" // historical scan — no IMAP actions taken automatically
)

// Action constants for AuditLog.Action.
const (
	ActionQuarantine = "QUARANTINE"
	ActionBackfill   = "BACKFILL"
	ActionRelease    = "RELEASE"
	ActionDelete     = "DELETE"
	ActionLearnHam   = "LEARN_HAM"
	ActionLearnSpam  = "LEARN_SPAM"
	ActionRescan     = "RESCAN"
	ActionWhitelist       = "WHITELIST"
	ActionBlocklist       = "BLOCKLIST"
	ActionRetroQuarantine = "RETRO_QUARANTINE"
)

// Verdict constants.
const (
	VerdictClean      = "CLEAN"
	VerdictSpam       = "SPAM"
	VerdictPhish      = "PHISH"
	VerdictMalware    = "MALWARE"
	VerdictSuspicious = "SUSPICIOUS"
)

// Status constants.
const (
	StatusInbox       = "INBOX"
	StatusQuarantined = "QUARANTINED"
	StatusReleased    = "RELEASED"
	StatusDeleted     = "DELETED"
	StatusLearnedHam  = "LEARNED_HAM"
	StatusLearnedSpam = "LEARNED_SPAM"
)
