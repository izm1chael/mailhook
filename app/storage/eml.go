package storage

import (
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/izm1chael/mailhook/util"
)

// Store manages raw EML files on disk under a date-partitioned directory tree.
type Store struct {
	dataDir string
	log     *slog.Logger
}

// New creates a Store rooted at dataDir/emls. The directory is created if absent.
func New(dataDir string, log *slog.Logger) (*Store, error) {
	root := filepath.Join(dataDir, "emls")
	if err := os.MkdirAll(root, 0o750); err != nil {
		return nil, fmt.Errorf("create eml store dir: %w", err)
	}
	return &Store{dataDir: dataDir, log: log}, nil
}

// Write persists raw EML bytes to disk and returns the relative path.
// Path scheme: emls/YYYY/MM/DD/<sha256-of-"accountName:messageID:uid">.eml
// The account name and IMAP UID are included in the hash key so that:
//   - Reused Message-IDs (common in spam) produce distinct filenames per UID.
//   - The same UID on different accounts (UID counters are per-mailbox, not global)
//     produces distinct filenames, preventing cross-account file collisions.
func (s *Store) Write(accountName, messageID string, uid uint32, raw []byte) (string, error) {
	now := time.Now()
	dir := filepath.Join(s.dataDir, "emls",
		now.Format("2006"), now.Format("01"), now.Format("02"))

	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", fmt.Errorf("create date dir: %w", err)
	}

	filename := util.SHA256Hex([]byte(fmt.Sprintf("%s:%s:%d", accountName, messageID, uid))) + ".eml"
	absPath := filepath.Join(dir, filename)
	relPath := filepath.Join("emls", now.Format("2006"), now.Format("01"), now.Format("02"), filename)

	if err := os.WriteFile(absPath, raw, 0o640); err != nil {
		return "", fmt.Errorf("write eml: %w", err)
	}
	return relPath, nil
}

// Read returns the raw EML bytes for the stored message.
func (s *Store) Read(relPath string) ([]byte, error) {
	absPath, err := s.safeAbs(relPath)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(absPath)
}

// Delete removes the EML file at relPath.
func (s *Store) Delete(relPath string) error {
	absPath, err := s.safeAbs(relPath)
	if err != nil {
		return err
	}
	if err := os.Remove(absPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("delete eml: %w", err)
	}
	return nil
}

// PurgeOlderThan removes EML files whose modification time is older than age,
// skipping any path present in protectedPaths (e.g. quarantined scan EMLs that
// have their own longer retention policy). protectedPaths keys are relative paths
// as returned by Write (e.g. "emls/2024/01/02/<hash>.eml").
// Returns the number of files deleted and any non-fatal error encountered.
func (s *Store) PurgeOlderThan(age time.Duration, protectedPaths map[string]struct{}) (int, error) {
	root := filepath.Join(s.dataDir, "emls")
	cutoff := time.Now().Add(-age)
	var deleted int

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries
		}
		if d.IsDir() || !strings.HasSuffix(path, ".eml") {
			return nil
		}
		rel, relErr := filepath.Rel(s.dataDir, path)
		if relErr != nil {
			return nil
		}
		if _, protected := protectedPaths[rel]; protected {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		if info.ModTime().Before(cutoff) {
			if removeErr := os.Remove(path); removeErr == nil {
				deleted++
				s.log.Debug("purged eml", "path", path, "age", time.Since(info.ModTime()).Round(time.Hour))
			}
		}
		return nil
	})

	return deleted, err
}

// ReconcileOrphans removes .eml files on disk that are not present in knownPaths.
// knownPaths should contain all eml_path values from the scans table. This catches
// files written before a DB insert that failed or was interrupted by a crash.
//
// Files younger than 1 hour are never deleted: a pipeline may have written the
// file but not yet committed the DB record (the scan + all scanners can take up
// to ~10 s). Deleting a fresh file would corrupt an in-flight pipeline run.
func (s *Store) ReconcileOrphans(knownPaths map[string]struct{}) (int, error) {
	root := filepath.Join(s.dataDir, "emls")
	var deleted int
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".eml") {
			return nil
		}
		info, infoErr := d.Info()
		if infoErr != nil || time.Since(info.ModTime()) < time.Hour {
			return nil // skip unreadable or too-fresh entries
		}
		rel, relErr := filepath.Rel(s.dataDir, path)
		if relErr != nil {
			return nil
		}
		if _, ok := knownPaths[rel]; !ok {
			if os.Remove(path) == nil {
				deleted++
				s.log.Debug("orphaned eml removed", "path", rel)
			}
		}
		return nil
	})
	return deleted, err
}

// DirSize returns the total size in bytes of all files in the EML store.
func (s *Store) DirSize() (int64, error) {
	root := filepath.Join(s.dataDir, "emls")
	var total int64
	err := filepath.WalkDir(root, func(_ string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		total += info.Size()
		return nil
	})
	return total, err
}

// safeAbs resolves relPath under dataDir and guards against path traversal.
func (s *Store) safeAbs(relPath string) (string, error) {
	abs := filepath.Join(s.dataDir, relPath)
	clean := filepath.Clean(abs)
	root := filepath.Clean(s.dataDir)
	if !strings.HasPrefix(clean, root+string(filepath.Separator)) {
		return "", fmt.Errorf("path traversal attempt: %q", relPath)
	}
	return clean, nil
}
