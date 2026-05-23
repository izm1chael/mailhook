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

// Recovery periodically searches for UNSEEN messages that may have arrived while
// the listener was offline or between IDLE reconnects, and dispatches any that
// were not already processed.
type Recovery struct {
	account     config.AccountConfig
	gdb         *db.DB
	onEmail     OnEmailFn
	log         *slog.Logger
	dispatchSem chan struct{}
}

// NewRecovery creates a Recovery for the given account.
func NewRecovery(account config.AccountConfig, gdb *db.DB, onEmail OnEmailFn, log *slog.Logger) *Recovery {
	return &Recovery{
		account:     account,
		gdb:         gdb,
		onEmail:     onEmail,
		log:         log,
		dispatchSem: make(chan struct{}, 50),
	}
}

// Run starts a ticker that fires every 15 minutes to scan for missed messages.
// Blocks until ctx is cancelled.
func (r *Recovery) Run(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			r.log.Debug("running recovery scan", "account", r.account.Name)
			if err := r.scan(ctx); err != nil {
				r.log.Warn("recovery scan failed", "account", r.account.Name, "err", err)
			}
		case <-ctx.Done():
			return
		}
	}
}

func (r *Recovery) scan(ctx context.Context) error {
	addr := fmt.Sprintf("%s:%d", r.account.Host, r.account.Port)
	if r.account.TLSSkipVerify {
		r.log.Warn("TLS certificate verification disabled for IMAP recovery", "account", r.account.Name)
	}
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		ServerName:         r.account.Host,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: r.account.TLSSkipVerify, // #nosec G402 -- per-account opt-in (TLSSkipVerify); MITM risk warned in logs
	})
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}

	c := imapclient.New(conn, nil)
	defer c.Logout()

	if err := c.Login(r.account.User, r.account.Pass).Wait(); err != nil {
		return fmt.Errorf("login: %w", err)
	}
	if _, err := c.Select(r.account.Mailbox, nil).Wait(); err != nil {
		return fmt.Errorf("select: %w", err)
	}

	criteria := &imap.SearchCriteria{NotFlag: []imap.Flag{imap.FlagSeen}}
	searchData, err := c.Search(criteria, nil).Wait()
	if err != nil {
		return fmt.Errorf("search: %w", err)
	}
	seqNums := searchData.AllSeqNums()
	if len(seqNums) == 0 {
		return nil
	}

	// Fetch UIDs first to dedup against the DB before fetching full messages
	seqSet := imap.SeqSetNum(seqNums...)
	uidMessages, err := c.Fetch(seqSet, &imap.FetchOptions{UID: true}).Collect()
	if err != nil {
		return fmt.Errorf("fetch UIDs: %w", err)
	}

	var unknownSeqs []uint32
	for _, msg := range uidMessages {
		uid := uint32(msg.UID)
		accountUID := db.MakeAccountUID(r.account.Name, r.account.Mailbox, uid)
		var count int64
		r.gdb.Model(&db.Scan{}).Where("account_uid = ?", accountUID).Count(&count)
		if count == 0 {
			unknownSeqs = append(unknownSeqs, msg.SeqNum)
		}
	}

	if len(unknownSeqs) == 0 {
		return nil
	}

	r.log.Info("recovery found unprocessed messages",
		"account", r.account.Name, "count", len(unknownSeqs))

	// Fetch full RFC822 for unknown messages only.
	// Peek: true — do NOT auto-mark \Seen on FETCH; we mark explicitly below.
	fetchSet := imap.SeqSetNum(unknownSeqs...)
	fullMessages, err := c.Fetch(fetchSet, &imap.FetchOptions{
		UID:         true,
		BodySection: []*imap.FetchItemBodySection{{Peek: true}},
	}).Collect()
	if err != nil {
		return fmt.Errorf("fetch messages: %w", err)
	}

	var wg sync.WaitGroup
	var dispatchedUIDs []imap.UID

	for _, msg := range fullMessages {
		uid := uint32(msg.UID)
		var raw []byte
		for _, section := range msg.BodySection {
			raw = section.Bytes
			break
		}
		if len(raw) > 0 {
			r.dispatchSem <- struct{}{}
			wg.Add(1)
			dispatchedUIDs = append(dispatchedUIDs, imap.UID(uid))
			go func(raw []byte, uid uint32) {
				defer wg.Done()
				defer func() { <-r.dispatchSem }()
				r.onEmail(ctx, r.account.Name, raw, uid, r.account.Mailbox)
			}(raw, uid)
		}
	}

	// Wait for all dispatched goroutines to finish before marking \Seen,
	// so a crash during processing leaves the message UNSEEN for retry.
	wg.Wait()
	if len(dispatchedUIDs) > 0 {
		uidSet := imap.UIDSetNum(dispatchedUIDs...)
		storeData := &imap.StoreFlags{
			Op:     imap.StoreFlagsAdd,
			Flags:  []imap.Flag{imap.FlagSeen},
			Silent: true,
		}
		if err := c.Store(uidSet, storeData, nil).Close(); err != nil {
			r.log.Warn("recovery: batch \\Seen store failed", "account", r.account.Name, "err", err)
		}
	}

	return nil
}
