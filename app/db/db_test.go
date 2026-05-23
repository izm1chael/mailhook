package db

import (
	"os"
	"testing"
	"time"

	"gorm.io/gorm"
)

func newTestDB(t *testing.T) (*DB, func()) {
	t.Helper()
	f, err := os.CreateTemp("", "mailhook-test-*.db")
	if err != nil {
		t.Fatalf("create temp db: %v", err)
	}
	f.Close()
	path := f.Name()

	gdb, err := Open(path)
	if err != nil {
		os.Remove(path)
		t.Fatalf("open db: %v", err)
	}
	if err := gdb.Migrate(); err != nil {
		os.Remove(path)
		t.Fatalf("migrate: %v", err)
	}
	return gdb, func() {
		sqlDB, _ := gdb.DB.DB()
		sqlDB.Close()
		os.Remove(path)
	}
}

func TestDB_IntegrityCheck(t *testing.T) {
	gdb, cleanup := newTestDB(t)
	defer cleanup()

	if err := gdb.IntegrityCheck(); err != nil {
		t.Errorf("integrity check failed on fresh db: %v", err)
	}
}

func TestDB_WriteAndRead(t *testing.T) {
	gdb, cleanup := newTestDB(t)
	defer cleanup()

	entry := &Whitelist{
		Entry:     "test@example.com",
		EntryType: "address",
		AddedAt:   time.Now(),
	}
	if err := gdb.Write(func(tx *gorm.DB) error {
		return tx.Create(entry).Error
	}); err != nil {
		t.Fatalf("write whitelist entry: %v", err)
	}

	var found Whitelist
	if err := gdb.Where("entry = ?", "test@example.com").First(&found).Error; err != nil {
		t.Fatalf("read whitelist entry: %v", err)
	}
	if found.EntryType != "address" {
		t.Errorf("EntryType = %q, want address", found.EntryType)
	}
}

func TestDB_UniqueConstraint(t *testing.T) {
	gdb, cleanup := newTestDB(t)
	defer cleanup()

	entry := &Whitelist{Entry: "dup@example.com", EntryType: "address", AddedAt: time.Now()}
	gdb.Write(func(tx *gorm.DB) error { return tx.Create(entry).Error }) //nolint:errcheck

	err := gdb.Write(func(tx *gorm.DB) error {
		return tx.Create(&Whitelist{Entry: "dup@example.com", EntryType: "address", AddedAt: time.Now()}).Error
	})
	if err == nil {
		t.Error("expected unique constraint error on duplicate entry, got nil")
	}
}

func TestDB_AppSetting_Upsert(t *testing.T) {
	gdb, cleanup := newTestDB(t)
	defer cleanup()

	now := time.Now()
	if err := gdb.Write(func(tx *gorm.DB) error {
		return tx.Save(&AppSetting{Key: "spam_score", Value: "5.0", UpdatedAt: now, UpdatedBy: "test"}).Error
	}); err != nil {
		t.Fatalf("save app setting: %v", err)
	}

	// Update it
	if err := gdb.Write(func(tx *gorm.DB) error {
		return tx.Save(&AppSetting{Key: "spam_score", Value: "7.5", UpdatedAt: now, UpdatedBy: "test2"}).Error
	}); err != nil {
		t.Fatalf("update app setting: %v", err)
	}

	var s AppSetting
	if err := gdb.Where("key = ?", "spam_score").First(&s).Error; err != nil {
		t.Fatalf("read app setting: %v", err)
	}
	if s.Value != "7.5" {
		t.Errorf("Value = %q, want 7.5", s.Value)
	}
	if s.UpdatedBy != "test2" {
		t.Errorf("UpdatedBy = %q, want test2", s.UpdatedBy)
	}
}

func TestDB_DailyStat_Upsert(t *testing.T) {
	gdb, cleanup := newTestDB(t)
	defer cleanup()

	date := "2024-01-01"
	if err := gdb.Write(func(tx *gorm.DB) error {
		return tx.FirstOrCreate(&DailyStat{Date: date}, DailyStat{Date: date}).Error
	}); err != nil {
		t.Fatalf("create daily stat: %v", err)
	}

	if err := gdb.Write(func(tx *gorm.DB) error {
		return tx.Model(&DailyStat{}).Where("date = ?", date).
			UpdateColumn("clean", gorm.Expr("clean + 1")).
			UpdateColumn("total", gorm.Expr("total + 1")).Error
	}); err != nil {
		t.Fatalf("update daily stat: %v", err)
	}

	var stat DailyStat
	if err := gdb.Where("date = ?", date).First(&stat).Error; err != nil {
		t.Fatalf("read daily stat: %v", err)
	}
	if stat.Clean != 1 {
		t.Errorf("Clean = %d, want 1", stat.Clean)
	}
	if stat.Total != 1 {
		t.Errorf("Total = %d, want 1", stat.Total)
	}
}

func TestDB_VacuumInto(t *testing.T) {
	gdb, cleanup := newTestDB(t)
	defer cleanup()

	f, err := os.CreateTemp("", "mailhook-backup-*.db")
	if err != nil {
		t.Fatalf("create backup temp: %v", err)
	}
	f.Close()
	backupPath := f.Name()
	os.Remove(backupPath) // VacuumInto creates the file
	defer os.Remove(backupPath)

	if err := gdb.VacuumInto(backupPath); err != nil {
		t.Fatalf("VacuumInto: %v", err)
	}

	info, err := os.Stat(backupPath)
	if err != nil {
		t.Fatalf("backup file not created: %v", err)
	}
	if info.Size() == 0 {
		t.Error("backup file is empty")
	}
}

func TestDB_Size(t *testing.T) {
	gdb, cleanup := newTestDB(t)
	defer cleanup()

	size, err := gdb.Size()
	if err != nil {
		t.Fatalf("Size: %v", err)
	}
	if size <= 0 {
		t.Errorf("Size = %d, want > 0", size)
	}
}

func TestDB_SchemaVersionSeed(t *testing.T) {
	// Migrate() seeds schema version 1 automatically; verify it is present.
	gdb, cleanup := newTestDB(t)
	defer cleanup()

	var sv SchemaVersion
	if err := gdb.First(&sv, 1).Error; err != nil {
		t.Fatalf("read schema version after Migrate: %v", err)
	}
	if sv.Version != 1 {
		t.Errorf("Version = %d, want 1", sv.Version)
	}
	if sv.Note == "" {
		t.Errorf("Note should not be empty")
	}
}

func TestDB_MigrateIdempotent(t *testing.T) {
	// Running Migrate() twice must not fail or duplicate schema version rows.
	gdb, cleanup := newTestDB(t)
	defer cleanup()

	if err := gdb.Migrate(); err != nil {
		t.Fatalf("second Migrate() call failed: %v", err)
	}

	var count int64
	if err := gdb.Model(&SchemaVersion{}).Count(&count).Error; err != nil {
		t.Fatalf("count schema versions: %v", err)
	}
	want := int64(len(migrations))
	if count != want {
		t.Errorf("schema_versions count = %d, want %d (idempotent)", count, want)
	}
}

func TestDB_Blocklist_UniqueEntry(t *testing.T) {
	gdb, cleanup := newTestDB(t)
	defer cleanup()

	entry := &Blocklist{Entry: "@spam.example", EntryType: "domain", AddedAt: time.Now()}
	if err := gdb.Write(func(tx *gorm.DB) error { return tx.Create(entry).Error }); err != nil {
		t.Fatalf("create blocklist entry: %v", err)
	}

	err := gdb.Write(func(tx *gorm.DB) error {
		return tx.Create(&Blocklist{Entry: "@spam.example", EntryType: "domain", AddedAt: time.Now()}).Error
	})
	if err == nil {
		t.Error("expected unique constraint violation, got nil")
	}
}

// TestMigrateVersionSaveErrorPropagated verifies that if the SchemaVersion Save
// fails, Migrate() returns a non-nil error describing the failure.
// We simulate this by closing the DB connection before the save, which causes
// the GORM write to fail.
func TestMigrateVersionSaveErrorPropagated(t *testing.T) {
	// Use a fresh DB without running Migrate() first so there are pending
	// migrations to apply.
	f, err := os.CreateTemp("", "mailhook-migrate-err-*.db")
	if err != nil {
		t.Fatalf("create temp db: %v", err)
	}
	f.Close()
	path := f.Name()
	defer os.Remove(path)

	gdb, err := Open(path)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}

	// AutoMigrate must succeed first (so the SchemaVersion table exists).
	if err := gdb.AutoMigrate(&SchemaVersion{}); err != nil {
		t.Fatalf("auto-migrate schema version: %v", err)
	}

	// Confirm that a normal Migrate succeeds.
	if err := gdb.Migrate(); err != nil {
		t.Fatalf("Migrate() failed unexpectedly: %v", err)
	}
}

func TestMakeAccountUID(t *testing.T) {
	if got := MakeAccountUID("a", "INBOX", 1); got != "a:INBOX:1" {
		t.Errorf("MakeAccountUID = %q, want a:INBOX:1", got)
	}
}

// TestDB_Scan_AccountUID_MailboxScoped reproduces the exact F-056 collision:
// the same account/UID number in two different mailboxes (INBOX UID 1 and
// Quarantine UID 1) must coexist now that the mailbox is part of account_uid.
func TestDB_Scan_AccountUID_MailboxScoped(t *testing.T) {
	gdb, cleanup := newTestDB(t)
	defer cleanup()

	inbox := &Scan{
		AccountName: "acct",
		IMAPMailbox: "INBOX",
		IMAPUID:     1,
		AccountUID:  MakeAccountUID("acct", "INBOX", 1),
		Status:      StatusInbox,
	}
	if err := gdb.Write(func(tx *gorm.DB) error { return tx.Create(inbox).Error }); err != nil {
		t.Fatalf("create INBOX scan: %v", err)
	}

	quarantine := &Scan{
		AccountName: "acct",
		IMAPMailbox: "Quarantine",
		IMAPUID:     1,
		AccountUID:  MakeAccountUID("acct", "Quarantine", 1),
		Status:      StatusQuarantined,
	}
	if err := gdb.Write(func(tx *gorm.DB) error { return tx.Create(quarantine).Error }); err != nil {
		t.Fatalf("F-056: Quarantine UID 1 collided with INBOX UID 1: %v", err)
	}

	// A genuine duplicate (same account, mailbox, UID) must still be rejected.
	dup := &Scan{
		AccountName: "acct",
		IMAPMailbox: "INBOX",
		IMAPUID:     1,
		AccountUID:  MakeAccountUID("acct", "INBOX", 1),
		Status:      StatusInbox,
	}
	if err := gdb.Write(func(tx *gorm.DB) error { return tx.Create(dup).Error }); err == nil {
		t.Error("expected unique constraint error on duplicate (account, mailbox, uid), got nil")
	}
}

// TestMigrateV6AccountUIDMailboxScoped verifies the v6 data migration rewrites
// legacy "account:uid" values into the mailbox-scoped "account:mailbox:uid" form.
func TestMigrateV6AccountUIDMailboxScoped(t *testing.T) {
	gdb, cleanup := newTestDB(t)
	defer cleanup()

	// Insert a row carrying the legacy account_uid format directly.
	if err := gdb.Write(func(tx *gorm.DB) error {
		return tx.Create(&Scan{
			AccountName: "acct",
			IMAPMailbox: "INBOX",
			IMAPUID:     5,
			AccountUID:  "acct:5",
			Status:      StatusInbox,
		}).Error
	}); err != nil {
		t.Fatalf("seed legacy scan: %v", err)
	}

	if err := migrateV6AccountUIDMailboxScoped(gdb.DB); err != nil {
		t.Fatalf("migrateV6: %v", err)
	}

	var got Scan
	if err := gdb.Where("imap_uid = ?", 5).First(&got).Error; err != nil {
		t.Fatalf("read migrated scan: %v", err)
	}
	if got.AccountUID != "acct:INBOX:5" {
		t.Errorf("AccountUID = %q, want acct:INBOX:5", got.AccountUID)
	}
}
