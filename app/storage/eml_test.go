package storage

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newTestStore(t *testing.T) (*Store, func()) {
	t.Helper()
	dir, err := os.MkdirTemp("", "mailhook-store-*")
	if err != nil {
		t.Fatalf("mkdirtemp: %v", err)
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	store, err := New(dir, log)
	if err != nil {
		os.RemoveAll(dir)
		t.Fatalf("new store: %v", err)
	}
	return store, func() { os.RemoveAll(dir) }
}

func TestStore_WriteRead(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	raw := []byte("From: test@example.com\r\n\r\nBody")
	relPath, err := store.Write("acct1", "<test-msg-001@example.com>", 1, raw)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if relPath == "" {
		t.Fatal("relPath should not be empty")
	}

	got, err := store.Read(relPath)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(got) != string(raw) {
		t.Errorf("Read returned %q, want %q", got, raw)
	}
}

func TestStore_Write_SameIDIdempotent(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	raw := []byte("test content")
	msgID := "<idempotent@example.com>"

	path1, err := store.Write("acct1", msgID, 1, raw)
	if err != nil {
		t.Fatalf("first Write: %v", err)
	}
	path2, err := store.Write("acct1", msgID, 1, raw)
	if err != nil {
		t.Fatalf("second Write: %v", err)
	}
	if path1 != path2 {
		t.Errorf("expected same path for same account+messageID+uid: %q vs %q", path1, path2)
	}
}

// TestStore_Write_CrossAccountNoCollision verifies that two accounts with the same
// Message-ID and IMAP UID produce distinct file paths (UID counters are per-mailbox).
func TestStore_Write_CrossAccountNoCollision(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	msgID := "<same-campaign@spam.example>"
	uid := uint32(45012)
	raw := []byte("spam content")

	path1, err := store.Write("personal", msgID, uid, raw)
	if err != nil {
		t.Fatalf("Write account1: %v", err)
	}
	path2, err := store.Write("security", msgID, uid, raw)
	if err != nil {
		t.Fatalf("Write account2: %v", err)
	}
	if path1 == path2 {
		t.Errorf("cross-account collision: same path %q for different accounts", path1)
	}
}

func TestStore_Delete(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	raw := []byte("delete me")
	relPath, _ := store.Write("acct1", "<delete-test@example.com>", 1, raw)

	if err := store.Delete(relPath); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	// Second delete should not error (already gone)
	if err := store.Delete(relPath); err != nil {
		t.Errorf("Delete of non-existent should not error: %v", err)
	}

	// Read should fail
	if _, err := store.Read(relPath); err == nil {
		t.Error("expected Read error after Delete")
	}
}

func TestStore_PathTraversal(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	if _, err := store.Read("../../etc/passwd"); err == nil {
		t.Error("expected path traversal error, got nil")
	}
	if _, err := store.Read("../../../root/.ssh/id_rsa"); err == nil {
		t.Error("expected path traversal error, got nil")
	}
}

func TestStore_DirSize(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	// Empty store
	size, err := store.DirSize()
	if err != nil {
		t.Fatalf("DirSize on empty: %v", err)
	}
	if size != 0 {
		t.Errorf("empty store size = %d, want 0", size)
	}

	// After write
	raw := []byte("some content for size test")
	store.Write("acct1", "<size-test@example.com>", 1, raw) //nolint:errcheck

	size2, err := store.DirSize()
	if err != nil {
		t.Fatalf("DirSize after write: %v", err)
	}
	if size2 <= 0 {
		t.Errorf("expected positive size after write, got %d", size2)
	}
}

func TestStore_PurgeOlderThan(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	raw := []byte("old content")
	relPath, err := store.Write("acct1", "<old-msg@example.com>", 1, raw)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	// Purge with 0 age — should delete everything modified before now
	// Use a very short max-age so the just-written file qualifies
	n, err := store.PurgeOlderThan(0, nil)
	if err != nil {
		t.Fatalf("PurgeOlderThan: %v", err)
	}
	if n == 0 {
		t.Error("expected at least 1 file purged")
	}

	// File should be gone
	if _, err := store.Read(relPath); err == nil {
		t.Error("expected Read error after purge")
	}
}

func TestStore_PurgeOlderThan_KeepsRecent(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	raw := []byte("recent content")
	relPath, _ := store.Write("acct1", "<recent@example.com>", 1, raw)

	// Purge with 24h age — just-written file should survive
	n, err := store.PurgeOlderThan(24*time.Hour, nil)
	if err != nil {
		t.Fatalf("PurgeOlderThan: %v", err)
	}
	if n != 0 {
		t.Errorf("expected 0 purged for recent file, got %d", n)
	}

	// File should still be readable
	if _, err := store.Read(relPath); err != nil {
		t.Errorf("recent file should survive purge: %v", err)
	}
}

// TestStore_PurgeOlderThan_SkipsProtected verifies that paths in the protected set
// (e.g. quarantined EML paths) are never deleted, even if they are old enough.
func TestStore_PurgeOlderThan_SkipsProtected(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	raw := []byte("quarantined evidence")
	quarantinedPath, err := store.Write("acct1", "<quarantine@example.com>", 10, raw)
	if err != nil {
		t.Fatalf("Write quarantined: %v", err)
	}
	normalPath, err := store.Write("acct1", "<normal@example.com>", 11, raw)
	if err != nil {
		t.Fatalf("Write normal: %v", err)
	}

	protected := map[string]struct{}{quarantinedPath: {}}
	n, err := store.PurgeOlderThan(0, protected)
	if err != nil {
		t.Fatalf("PurgeOlderThan: %v", err)
	}
	if n != 1 {
		t.Errorf("expected 1 file purged (the non-protected one), got %d", n)
	}

	// Quarantined file must survive
	if _, err := store.Read(quarantinedPath); err != nil {
		t.Errorf("quarantined file should not be purged: %v", err)
	}
	// Normal file must be gone
	if _, err := store.Read(normalPath); err == nil {
		t.Error("normal file should have been purged")
	}
}

// TestStore_ReconcileOrphans_SkipsFreshFiles verifies that ReconcileOrphans does not
// delete files that are less than 1 hour old (in-flight pipeline protection).
func TestStore_ReconcileOrphans_SkipsFreshFiles(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	raw := []byte("in-flight eml")
	relPath, err := store.Write("acct1", "<inflight@example.com>", 99, raw)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	// File is fresh (just written), not in knownPaths — should NOT be deleted.
	known := map[string]struct{}{} // intentionally empty
	n, err := store.ReconcileOrphans(known)
	if err != nil {
		t.Fatalf("ReconcileOrphans: %v", err)
	}
	if n != 0 {
		t.Errorf("expected 0 deleted (fresh file), got %d", n)
	}

	// File should still exist
	if _, err := store.Read(relPath); err != nil {
		t.Errorf("fresh file should not be deleted by orphan reaper: %v", err)
	}
}

// TestStore_ReconcileOrphans_DeletesOldOrphans verifies that files older than 1 hour
// that are not in knownPaths are removed.
func TestStore_ReconcileOrphans_DeletesOldOrphans(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	raw := []byte("old orphan")
	relPath, err := store.Write("acct1", "<orphan@example.com>", 77, raw)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	// Back-date the file by 2 hours to simulate an old orphan.
	absPath := filepath.Join(store.dataDir, relPath)
	past := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(absPath, past, past); err != nil {
		t.Fatalf("Chtimes: %v", err)
	}

	known := map[string]struct{}{} // not in DB
	n, err := store.ReconcileOrphans(known)
	if err != nil {
		t.Fatalf("ReconcileOrphans: %v", err)
	}
	if n != 1 {
		t.Errorf("expected 1 deleted (old orphan), got %d", n)
	}

	// File should be gone
	if _, err := store.Read(relPath); err == nil {
		t.Error("old orphan should have been deleted")
	}
}

// TestStore_ReconcileOrphans_KeepsKnownFiles verifies that files present in
// knownPaths are never deleted, regardless of age.
func TestStore_ReconcileOrphans_KeepsKnownFiles(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	raw := []byte("known file")
	relPath, err := store.Write("acct1", "<known@example.com>", 55, raw)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	// Back-date to make it old enough for deletion if it were an orphan.
	absPath := filepath.Join(store.dataDir, relPath)
	past := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(absPath, past, past); err != nil {
		t.Fatalf("Chtimes: %v", err)
	}

	known := map[string]struct{}{relPath: {}}
	n, err := store.ReconcileOrphans(known)
	if err != nil {
		t.Fatalf("ReconcileOrphans: %v", err)
	}
	if n != 0 {
		t.Errorf("expected 0 deleted (file is known), got %d", n)
	}
}
