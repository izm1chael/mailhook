package db

import (
	"fmt"
	"time"

	"gorm.io/gorm"
)

// versionedMigration describes a schema version and an optional data-transform function.
// fn may be nil when AutoMigrate alone is sufficient for that version (additive-only changes).
type versionedMigration struct {
	version int
	note    string
	fn      func(*gorm.DB) error
}

// migrations is the ordered list of all schema versions. New entries are appended here;
// existing entries must never be modified once the version has been deployed.
var migrations = []versionedMigration{
	{1, "initial schema", nil},
	{2, "add nrd_cache table and resolved_url_hits/nrd_hits columns to scans", nil},
	{3, "add html_smuggling_hits and hidden_text_hits columns to scans", nil},
	{4, "add malware_bazaar_hashes table and mb_results column on scans", nil},
	{5, "add scanned_urls column to scans for retrospective scanning", nil},
	{6, "rebuild account_uid as account:mailbox:uid (F-056)", migrateV6AccountUIDMailboxScoped},
	{7, "add source column to scans and backfill_days to accounts", nil},
}

// migrateV6AccountUIDMailboxScoped rewrites existing scans.account_uid from the
// old "account:uid" format to the mailbox-scoped "account:mailbox:uid" format so
// post-upgrade dedup lookups still match (F-056). COALESCE guards against NULL
// imap_mailbox (NULL concatenation would otherwise null the whole value).
// Idempotent: recomputed purely from the stable account_name/imap_mailbox/imap_uid
// columns, so re-running yields the same result.
func migrateV6AccountUIDMailboxScoped(tx *gorm.DB) error {
	return tx.Exec(
		"UPDATE scans SET account_uid = account_name || ':' || COALESCE(imap_mailbox,'') || ':' || imap_uid",
	).Error
}

// Migrate runs GORM AutoMigrate for all models (additive-only, safe on every startup),
// then applies any versioned migrations that have not yet been recorded in SchemaVersion.
// This replaces the standalone seedSchemaVersion call in main.go.
func (d *DB) Migrate() error {
	models := []interface{}{
		&SchemaVersion{},
		&Scan{},
		&IPReputationCache{},
		&VTHashCache{},
		&FeedMeta{},
		&Session{},
		&AuditLog{},
		&Whitelist{},
		&Blocklist{},
		&DailyStat{},
		&AppSetting{},
		&Account{},
		&CustomFeedEntry{},
		&NRDCache{},
		&MalwareBazaarHash{},
	}
	for _, m := range models {
		if err := d.AutoMigrate(m); err != nil {
			return fmt.Errorf("automigrate %T: %w", m, err)
		}
	}

	// Determine the highest version already applied.
	var current SchemaVersion
	d.DB.Order("version desc").First(&current) // version stays 0 if table is empty

	for _, m := range migrations {
		if m.version <= current.Version {
			continue
		}
		if m.fn != nil {
			if err := m.fn(d.DB); err != nil {
				return fmt.Errorf("migration v%d (%s): %w", m.version, m.note, err)
			}
		}
		// NOTE: future non-nil fn migrations should wrap both m.fn and this Save
		// in a single Begin()/Commit() for true atomicity.
		if err := d.Write(func(tx *gorm.DB) error {
			return tx.Save(&SchemaVersion{
				Version:   m.version,
				AppliedAt: time.Now(),
				Note:      m.note,
			}).Error
		}); err != nil {
			return fmt.Errorf("migration v%d: version save: %w", m.version, err)
		}
		current.Version = m.version
	}
	return nil
}
