package auth

import (
	"os"
	"testing"
	"time"

	"github.com/izm1chael/mailhook/db"
	"gorm.io/gorm"
)

func newTestDB(t *testing.T) (*db.DB, func()) {
	t.Helper()
	f, err := os.CreateTemp("", "mailhook-auth-test-*.db")
	if err != nil {
		t.Fatalf("create temp db: %v", err)
	}
	f.Close()
	path := f.Name()

	gdb, err := db.Open(path)
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

// TestLoadFromDB_SessionSurvivesRestart verifies that a session persisted to the DB
// is restored on the next startup and immediately accessible via Get — without being
// treated as idle-expired due to a zero LastSeenAt.
func TestLoadFromDB_SessionSurvivesRestart(t *testing.T) {
	gdb, cleanup := newTestDB(t)
	defer cleanup()

	store := NewStore(24 * time.Hour)
	token := store.Create("admin", "127.0.0.1")

	if err := store.PersistToDB(gdb); err != nil {
		t.Fatalf("PersistToDB: %v", err)
	}

	// Simulate restart: create a fresh store and load from DB.
	store2 := NewStore(24 * time.Hour)
	store2.LoadFromDB(gdb)

	sess, ok := store2.Get(token)
	if !ok {
		t.Fatal("session should be present after LoadFromDB — not idle-expired")
	}
	if sess.Username != "admin" {
		t.Errorf("username = %q, want %q", sess.Username, "admin")
	}
}

// TestLoadFromDB_ExpiredSessionNotRestored verifies that already-expired sessions
// in the DB are not loaded into memory.
func TestLoadFromDB_ExpiredSessionNotRestored(t *testing.T) {
	gdb, cleanup := newTestDB(t)
	defer cleanup()

	// Insert an already-expired session directly into the DB.
	past := time.Now().Add(-time.Hour)
	expired := db.Session{
		Token:     "expired-token-abc123",
		Username:  "admin",
		IPAddr:    "127.0.0.1",
		CreatedAt: past.Add(-time.Hour),
		ExpiresAt: past,
	}
	gdb.Write(func(tx *gorm.DB) error { return tx.Create(&expired).Error }) //nolint:errcheck

	store := NewStore(24 * time.Hour)
	store.LoadFromDB(gdb)

	if _, ok := store.Get("expired-token-abc123"); ok {
		t.Error("expired session should not be restored")
	}
}
