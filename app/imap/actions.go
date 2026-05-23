package imap

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/izm1chael/mailhook/config"
)

// Actions performs IMAP mutations (move, delete, flag) on messages.
// Each method opens a dedicated TLS connection so the IDLE listener connection
// is never interrupted.
type Actions struct {
	account config.AccountConfig
	log     *slog.Logger
}

// NewActions returns an Actions bound to the given account.
func NewActions(account config.AccountConfig, log *slog.Logger) *Actions {
	return &Actions{account: account, log: log}
}

// freshClient dials a new authenticated IMAP connection for the account.
// It honors ctx for both the TCP dial and subsequent command deadlines.
func (a *Actions) freshClient(ctx context.Context) (*imapclient.Client, error) {
	addr := fmt.Sprintf("%s:%d", a.account.Host, a.account.Port)
	tlsCfg := &tls.Config{
		ServerName:         a.account.Host,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: a.account.TLSSkipVerify, //nolint:gosec
	}

	conn, err := (&tls.Dialer{Config: tlsCfg}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}

	// Propagate ctx deadline to all subsequent I/O on this connection.
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline) //nolint:errcheck
	}

	c := imapclient.New(conn, nil)

	if err := c.Login(a.account.User, a.account.Pass).Wait(); err != nil {
		c.Close()
		return nil, fmt.Errorf("login %s: %w", a.account.User, err)
	}

	return c, nil
}

// MoveToQuarantine moves uid from mailbox to the configured quarantine folder.
// Returns the new UID assigned by the server in the quarantine folder (from the
// COPYUID response), the quarantine folder name, and any error. On success,
// newUID is >0 when the server provides COPYUID; it is 0 when the server emits
// a malformed COPYUID response (e.g. GreenMail) but the message left the source
// (F-054 fallback). Callers should persist newUID and the returned mailbox name
// to keep the DB in sync (F-056).
func (a *Actions) MoveToQuarantine(ctx context.Context, mailbox string, uid uint32) (newUID uint32, newMailbox string, err error) {
	err = withRetry(ctx, 3, 500*time.Millisecond, func() error {
		return a.withSelectedMailbox(ctx, mailbox, func(c *imapclient.Client) error {
			uidSet := imap.UIDSetNum(imap.UID(uid))
			moveData, moveErr := c.Move(uidSet, a.account.Quarantine).Wait()
			if moveErr != nil {
				return moveErr
			}
			// Extract the new UID from the COPYUID/MOVEUID response code.
			// DestUIDs is typed as NumSet (interface); assert to UIDSet to index.
			if moveData != nil && moveData.DestUIDs != nil {
				if destUIDs, ok := moveData.DestUIDs.(imap.UIDSet); ok && len(destUIDs) > 0 {
					newUID = uint32(destUIDs[0].Start)
				}
			}
			return nil
		})
	})
	if err == nil {
		return newUID, a.account.Quarantine, nil
	}
	// F-054: some servers (e.g. GreenMail) complete the MOVE but emit a malformed
	// COPYUID response. Verify the message LEFT the source; if so, suppress the
	// error. newUID is 0 because we cannot recover the destination UID from a
	// malformed response — callers should update imap_mailbox at minimum.
	if stillThere, checkErr := a.MessageExists(ctx, mailbox, uid); checkErr == nil && !stillThere {
		a.log.Warn("MoveToQuarantine: move returned error but message absent from source — treating as success",
			"account", a.account.Name, "uid", uid, "source", mailbox, "move_err", err)
		return 0, a.account.Quarantine, nil
	}
	return 0, "", err
}

// MessageExists reports whether uid is present in mailbox.
// Exported so integration tests can verify the helper independently.
func (a *Actions) MessageExists(ctx context.Context, mailbox string, uid uint32) (bool, error) {
	var found bool
	err := a.withSelectedMailbox(ctx, mailbox, func(c *imapclient.Client) error {
		uidSet := imap.UIDSetNum(imap.UID(uid))
		criteria := &imap.SearchCriteria{UID: []imap.UIDSet{uidSet}}
		data, searchErr := c.UIDSearch(criteria, nil).Wait()
		if searchErr != nil {
			return searchErr
		}
		found = len(data.AllUIDs()) > 0
		return nil
	})
	return found, err
}

// ReleaseToInbox moves uid from the quarantine folder back to INBOX.
func (a *Actions) ReleaseToInbox(ctx context.Context, uid uint32) error {
	return withRetry(ctx, 3, 500*time.Millisecond, func() error {
		return a.withSelectedMailbox(ctx, a.account.Quarantine, func(c *imapclient.Client) error {
			uidSet := imap.UIDSetNum(imap.UID(uid))
			_, err := c.Move(uidSet, a.account.Mailbox).Wait()
			return err
		})
	})
}

// DeleteMessage permanently removes uid from mailbox via \Deleted + UID EXPUNGE.
// UID EXPUNGE (RFC 4315 UIDPLUS) scopes the expunge to the target UID only,
// preventing accidental deletion of other \Deleted messages in the mailbox.
func (a *Actions) DeleteMessage(ctx context.Context, mailbox string, uid uint32) error {
	return withRetry(ctx, 3, 500*time.Millisecond, func() error {
		return a.withSelectedMailbox(ctx, mailbox, func(c *imapclient.Client) error {
			uidSet := imap.UIDSetNum(imap.UID(uid))
			flags := &imap.StoreFlags{
				Op:     imap.StoreFlagsAdd,
				Flags:  []imap.Flag{imap.FlagDeleted},
				Silent: true,
			}
			if err := c.Store(uidSet, flags, nil).Close(); err != nil {
				return fmt.Errorf("store \\Deleted: %w", err)
			}
			return c.UIDExpunge(uidSet).Close()
		})
	})
}

// FlagMessage sets the \Flagged flag on uid without moving it.
func (a *Actions) FlagMessage(ctx context.Context, mailbox string, uid uint32) error {
	return withRetry(ctx, 3, 500*time.Millisecond, func() error {
		return a.withSelectedMailbox(ctx, mailbox, func(c *imapclient.Client) error {
			uidSet := imap.UIDSetNum(imap.UID(uid))
			flags := &imap.StoreFlags{
				Op:     imap.StoreFlagsAdd,
				Flags:  []imap.Flag{imap.FlagFlagged},
				Silent: true,
			}
			return c.Store(uidSet, flags, nil).Close()
		})
	})
}

// BulkReleaseToInbox moves all uids from the quarantine folder to INBOX in a single
// authenticated IMAP session, amortizing the TLS handshake + LOGIN cost.
func (a *Actions) BulkReleaseToInbox(ctx context.Context, uids []uint32) error {
	if len(uids) == 0 {
		return nil
	}
	return withRetry(ctx, 3, 500*time.Millisecond, func() error {
		return a.withSelectedMailbox(ctx, a.account.Quarantine, func(c *imapclient.Client) error {
			uidSet := uidsToSet(uids)
			_, err := c.Move(uidSet, a.account.Mailbox).Wait()
			return err
		})
	})
}

// BulkDeleteMessages flags all uids in mailbox as \Deleted and UID EXPUNGEs them
// in a single authenticated IMAP session.
func (a *Actions) BulkDeleteMessages(ctx context.Context, mailbox string, uids []uint32) error {
	if len(uids) == 0 {
		return nil
	}
	return withRetry(ctx, 3, 500*time.Millisecond, func() error {
		return a.withSelectedMailbox(ctx, mailbox, func(c *imapclient.Client) error {
			uidSet := uidsToSet(uids)
			flags := &imap.StoreFlags{
				Op:     imap.StoreFlagsAdd,
				Flags:  []imap.Flag{imap.FlagDeleted},
				Silent: true,
			}
			if err := c.Store(uidSet, flags, nil).Close(); err != nil {
				return fmt.Errorf("store \\Deleted: %w", err)
			}
			return c.UIDExpunge(uidSet).Close()
		})
	})
}

// uidsToSet builds an imap.UIDSet from a slice of UID values.
func uidsToSet(uids []uint32) imap.UIDSet {
	var s imap.UIDSet
	for _, uid := range uids {
		s.AddNum(imap.UID(uid))
	}
	return s
}

// EnsureFolderExists creates the quarantine folder if it does not exist.
func (a *Actions) EnsureFolderExists(ctx context.Context) error {
	c, err := a.freshClient(ctx)
	if err != nil {
		return err
	}
	defer c.Logout()

	listData, err := c.List("", a.account.Quarantine, nil).Collect()
	if err != nil {
		return fmt.Errorf("list folders: %w", err)
	}
	for _, mb := range listData {
		if mb.Mailbox == a.account.Quarantine {
			return nil // already exists
		}
	}

	a.log.Info("creating quarantine folder", "account", a.account.Name, "folder", a.account.Quarantine)
	return c.Create(a.account.Quarantine, nil).Wait()
}

// withRetry calls fn up to attempts times, waiting delay*2^i between failures.
// It honors ctx: if cancelled during a backoff sleep it returns ctx.Err() immediately.
func withRetry(ctx context.Context, attempts int, delay time.Duration, fn func() error) error {
	var err error
	for i := 0; i < attempts; i++ {
		if err = fn(); err == nil {
			return nil
		}
		if i < attempts-1 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay * (1 << uint(i))):
			}
		}
	}
	return err
}

// withSelectedMailbox opens a fresh connection, selects mailbox, runs fn, then logs out.
func (a *Actions) withSelectedMailbox(ctx context.Context, mailbox string, fn func(*imapclient.Client) error) error {
	c, err := a.freshClient(ctx)
	if err != nil {
		return err
	}
	defer c.Logout()

	if _, err := c.Select(mailbox, nil).Wait(); err != nil {
		return fmt.Errorf("select %s: %w", mailbox, err)
	}
	return fn(c)
}
