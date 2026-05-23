package db

import (
	"fmt"
	"sync"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// DB wraps a gorm.DB. Reads run concurrently via a small connection pool (WAL
// allows multiple concurrent readers). Writes are serialized through a mutex so
// only one transaction is in-flight at a time, which prevents SQLITE_BUSY under
// concurrent write load without needing MaxOpenConns(1) for the whole pool.
type DB struct {
	*gorm.DB
	writeMu sync.Mutex
}

// pragmasDSN holds all per-connection pragmas baked into the SQLite DSN so they
// are applied atomically at connection-open time, before any statement executes.
// _auto_vacuum=INCREMENTAL enables page-level reclaim via PRAGMA incremental_vacuum
// without a full blocking VACUUM; _journal_mode=WAL allows concurrent reads.
const pragmasDSN = "?_journal_mode=WAL&_busy_timeout=5000&_synchronous=NORMAL" +
	"&_foreign_keys=on&_cache_size=-65536&_temp_store=MEMORY&_auto_vacuum=INCREMENTAL"

// Open opens (or creates) the SQLite database at the given path, applies WAL-mode
// pragmas, and returns a ready-to-use DB.
func Open(path string) (*DB, error) {
	gormCfg := &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	}

	// Embed all pragmas in the DSN so they apply to every connection at open time.
	// This avoids pragma drift: if the pool ever briefly had >1 connection, pragmas
	// applied via db.Exec() might miss some connections.
	dsn := "file:" + path + pragmasDSN
	gdb, err := gorm.Open(sqlite.Open(dsn), gormCfg)
	if err != nil {
		return nil, fmt.Errorf("open sqlite %s: %w", path, err)
	}

	sqlDB, err := gdb.DB()
	if err != nil {
		return nil, fmt.Errorf("get sql.DB: %w", err)
	}

	// Allow multiple concurrent readers; WAL mode supports them alongside one writer.
	// Writes are serialized via DB.writeMu, so only one write transaction runs at a time.
	sqlDB.SetMaxOpenConns(4)
	sqlDB.SetMaxIdleConns(4)

	return &DB{DB: gdb}, nil
}

// Write executes fn inside a database transaction. The write mutex serializes
// concurrent callers so only one write transaction is in-flight at a time,
// preventing SQLITE_BUSY under write contention. fn runs atomically: if it
// returns an error the transaction is rolled back.
func (d *DB) Write(fn func(tx *gorm.DB) error) error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	return d.DB.Transaction(fn)
}

// QuickCheck runs a cheap liveness probe (SELECT 1) suitable for /health polling.
// Full integrity_check is O(DB size) and reserved for scheduled maintenance.
func (d *DB) QuickCheck() error {
	return d.Raw("SELECT 1").Scan(new(int)).Error
}

// IntegrityCheck runs SQLite integrity_check and returns nil if the database is healthy.
func (d *DB) IntegrityCheck() error {
	var result string
	if err := d.Raw("PRAGMA integrity_check").Scan(&result).Error; err != nil {
		return fmt.Errorf("integrity_check failed: %w", err)
	}
	if result != "ok" {
		return fmt.Errorf("integrity_check returned: %s", result)
	}
	return nil
}

// VacuumInto creates a compacted copy of the database at destPath using
// SQLite's online backup API (VACUUM INTO). Safe to call while readers/writers
// are active; the destination is always a consistent snapshot.
func (d *DB) VacuumInto(destPath string) error {
	return d.Exec("VACUUM INTO ?", destPath).Error
}

// Vacuum runs VACUUM to reclaim unused SQLite pages and defragment the file.
func (d *DB) Vacuum() error {
	return d.Exec("VACUUM").Error
}

// Size returns the current database file size in bytes.
func (d *DB) Size() (int64, error) {
	var pageCount, pageSize int64
	if err := d.Raw("PRAGMA page_count").Scan(&pageCount).Error; err != nil {
		return 0, err
	}
	if err := d.Raw("PRAGMA page_size").Scan(&pageSize).Error; err != nil {
		return 0, err
	}
	return pageCount * pageSize, nil
}
