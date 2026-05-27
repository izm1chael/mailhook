package imap

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/izm1chael/mailhook/config"
	"github.com/izm1chael/mailhook/db"
)

// BackfillScanner performs a one-shot historical scan of an IMAP mailbox.
// It fetches all messages (Seen and Unseen) within the configured window,
// skips any already recorded in the DB, and dispatches each unknown message
// through the backfill pipeline (no IMAP actions, observe-only).
type BackfillScanner struct {
	account     config.AccountConfig
	gdb         *db.DB
	onEmail     OnEmailFn
	log         *slog.Logger
	dispatchSem chan struct{}
}

// NewBackfillScanner creates a BackfillScanner for the given account.
func NewBackfillScanner(account config.AccountConfig, gdb *db.DB, onEmail OnEmailFn, log *slog.Logger) *BackfillScanner {
	return &BackfillScanner{
		account:     account,
		gdb:         gdb,
		onEmail:     onEmail,
		log:         log,
		dispatchSem: make(chan struct{}, 50),
	}
}

// Run executes the backfill scan once and returns. Designed to be called as a goroutine.
func (b *BackfillScanner) Run(ctx context.Context) {
	days := b.account.BackfillDays
	if days == 0 {
		return
	}

	var since string
	if days > 0 {
		since = fmt.Sprintf("last %d days", days)
	} else {
		since = "all time"
	}
	b.log.Info("backfill scanner starting",
		"account", b.account.Name, "window", since)

	if err := b.scan(ctx); err != nil {
		b.log.Warn("backfill scan failed", "account", b.account.Name, "err", err)
		return
	}
	b.log.Info("backfill scan complete", "account", b.account.Name)
}

func (b *BackfillScanner) scan(ctx context.Context) error {
	addr := fmt.Sprintf("%s:%d", b.account.Host, b.account.Port)
	if b.account.TLSSkipVerify {
		b.log.Warn("TLS certificate verification disabled for IMAP backfill", "account", b.account.Name)
	}
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		ServerName:         b.account.Host,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: b.account.TLSSkipVerify, // #nosec G402 -- per-account opt-in
	})
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}

	c := imapclient.New(conn, nil)
	defer c.Logout()

	if err := c.Login(b.account.User, b.account.Pass).Wait(); err != nil {
		return fmt.Errorf("login: %w", err)
	}
	if _, err := c.Select(b.account.Mailbox, nil).Wait(); err != nil {
		return fmt.Errorf("select: %w", err)
	}

	// Build search criteria: all messages (Seen + Unseen) within the window.
	criteria := &imap.SearchCriteria{}
	if b.account.BackfillDays > 0 {
		since := time.Now().AddDate(0, 0, -b.account.BackfillDays)
		criteria.Since = since
	}
	// BackfillDays == -1: empty criteria → SEARCH ALL (no date restriction).

	searchData, err := c.UIDSearch(criteria, nil).Wait()
	if err != nil {
		return fmt.Errorf("uid search: %w", err)
	}
	allUIDs := searchData.AllUIDs()
	if len(allUIDs) == 0 {
		b.log.Info("backfill: no messages in window", "account", b.account.Name)
		return nil
	}
	b.log.Info("backfill: found messages in window",
		"account", b.account.Name, "total", len(allUIDs))

	// Load all existing account_uids from the DB for this account+mailbox so we
	// can dedup without an individual query per message.
	var existing []struct{ IMAPUID uint32 }
	if err := b.gdb.Model(&db.Scan{}).
		Select("imap_uid").
		Where("account_name = ? AND imap_mailbox = ?", b.account.Name, b.account.Mailbox).
		Find(&existing).Error; err != nil {
		return fmt.Errorf("db uid lookup: %w", err)
	}
	knownUIDs := make(map[uint32]struct{}, len(existing))
	for _, e := range existing {
		knownUIDs[e.IMAPUID] = struct{}{}
	}

	var newUIDs []imap.UID
	for _, uid := range allUIDs {
		if _, seen := knownUIDs[uint32(uid)]; !seen {
			newUIDs = append(newUIDs, uid)
		}
	}
	if len(newUIDs) == 0 {
		b.log.Info("backfill: all messages already scanned", "account", b.account.Name)
		return nil
	}
	b.log.Info("backfill: scanning new messages",
		"account", b.account.Name, "count", len(newUIDs))

	// Stream message bodies one at a time with PEEK (never mutates \Seen).
	// Streaming via Next() instead of Collect() keeps memory proportional to
	// dispatchSem concurrency (50 bodies) rather than the full mailbox size,
	// which matters for backfill_days: -1 on a large inbox.
	uidSet := imap.UIDSetNum(newUIDs...)
	fetchCmd := c.Fetch(uidSet, &imap.FetchOptions{
		UID:         true,
		BodySection: []*imap.FetchItemBodySection{{Peek: true}},
	})
	defer fetchCmd.Close() //nolint:errcheck

	var wg sync.WaitGroup
	for {
		msgData := fetchCmd.Next()
		if msgData == nil {
			break
		}

		buf, err := msgData.Collect()
		if err != nil {
			b.log.Warn("backfill: message collect failed", "account", b.account.Name, "err", err)
			continue
		}

		uid := uint32(buf.UID)
		var raw []byte
		for _, section := range buf.BodySection {
			raw = section.Bytes
			break
		}
		if len(raw) == 0 {
			b.log.Warn("backfill: empty message body", "account", b.account.Name, "uid", uid)
			continue
		}

		// Acquire dispatch slot or abort cleanly on context cancellation.
		// Must return (not break) so the goroutine is never launched without
		// a slot — a bare break only exits the select and falls into wg.Add.
		select {
		case b.dispatchSem <- struct{}{}:
		case <-ctx.Done():
			wg.Wait()
			return nil
		}

		wg.Add(1)
		go func(raw []byte, uid uint32) {
			defer wg.Done()
			defer func() { <-b.dispatchSem }()
			b.onEmail(ctx, b.account.Name, raw, uid, b.account.Mailbox)
		}(raw, uid)
	}
	wg.Wait()
	return nil
}
