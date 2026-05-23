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
	"github.com/izm1chael/mailhook/metrics"
)

// OnEmailFn is called for each new email received. raw is the full RFC822 message.
// The function is invoked in a goroutine — implementations must be safe to call
// concurrently for different UIDs.
type OnEmailFn func(ctx context.Context, accountName string, raw []byte, uid uint32, mailbox string)

// Listener monitors one IMAP account via IDLE and dispatches new messages.
type Listener struct {
	account config.AccountConfig
	onEmail OnEmailFn
	log     *slog.Logger

	reconnectAttempts int
	// dispatchSem limits how many goroutines wait at the pipeline semaphore at
	// once, preventing memory exhaustion when connecting to a large existing inbox.
	dispatchSem chan struct{}
	// seenCh carries UIDs that have been fully processed and should be marked
	// \Seen on the server. Populated by dispatch goroutines after onEmail returns,
	// drained in the main poll loop so STORE commands stay on one goroutine.
	seenCh chan uint32
	// seenConfirmCh signals fetchUnseen to remove a UID from the in-flight set,
	// preventing re-dispatch on the next SEARCH UNSEEN iteration (F-029).
	seenConfirmCh chan uint32
	// inFlight tracks UIDs dispatched but not yet confirmed \Seen. Scoped to the
	// listener (not per-fetchUnseen call) so dedup persists across the connect-time
	// fetch and subsequent IDLE-triggered fetches within the same connection (F-055).
	// Reset at the start of each runOnce so reconnects start with a clean slate.
	inFlight map[uint32]struct{}
}

var reconnectDelays = []time.Duration{
	5 * time.Second,
	10 * time.Second,
	30 * time.Second,
	60 * time.Second,
	2 * time.Minute,
	5 * time.Minute,
}

// NewListener creates a Listener for the given account.
func NewListener(account config.AccountConfig, onEmail OnEmailFn, log *slog.Logger) *Listener {
	return &Listener{
		account:       account,
		onEmail:       onEmail,
		log:           log,
		dispatchSem:   make(chan struct{}, 50),
		seenCh:        make(chan uint32, 256),
		seenConfirmCh: make(chan uint32, 256),
		inFlight:      make(map[uint32]struct{}),
	}
}

// Run is the main loop. Connects, enters IDLE, dispatches new messages.
// Reconnects with exponential backoff on error. Blocks until ctx is cancelled.
func (l *Listener) Run(ctx context.Context) {
	l.log.Info("IMAP listener starting", "account", l.account.Name, "user", l.account.User)

	for {
		if ctx.Err() != nil {
			return
		}
		if err := l.runOnce(ctx); err != nil && ctx.Err() == nil {
			delay := reconnectDelays[min(l.reconnectAttempts, len(reconnectDelays)-1)]
			l.log.Warn("IMAP connection lost, reconnecting",
				"account", l.account.Name,
				"err", err,
				"delay", delay,
				"attempt", l.reconnectAttempts+1,
			)
			l.reconnectAttempts++
			metrics.IMAPReconnectsTotal.Inc()
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return
			}
		} else {
			l.reconnectAttempts = 0
		}
	}
}

func (l *Listener) runOnce(ctx context.Context) error {
	// Reset in-flight set for this connection. Any goroutines from a previous
	// connection that are still running may drain seenConfirmCh; deleting a
	// key that doesn't exist is a safe no-op, so there is no race.
	l.inFlight = make(map[uint32]struct{})

	// newMailCh is signalled by the UnilateralDataHandler when NumMessages changes.
	newMailCh := make(chan struct{}, 1)

	opts := &imapclient.Options{
		UnilateralDataHandler: &imapclient.UnilateralDataHandler{
			Mailbox: func(data *imapclient.UnilateralDataMailbox) {
				if data.NumMessages != nil {
					select {
					case newMailCh <- struct{}{}:
					default:
					}
				}
			},
		},
	}

	c, err := l.dial(opts)
	if err != nil {
		return err
	}
	defer c.Logout()

	if _, err := c.Select(l.account.Mailbox, nil).Wait(); err != nil {
		return fmt.Errorf("select %s: %w", l.account.Mailbox, err)
	}

	l.log.Info("IMAP connected", "account", l.account.Name, "mailbox", l.account.Mailbox)

	if err := l.fetchUnseen(ctx, c); err != nil {
		l.log.Warn("initial UNSEEN fetch failed", "account", l.account.Name, "err", err)
	}

	return l.idleLoop(ctx, c, newMailCh)
}

func (l *Listener) idleLoop(ctx context.Context, c *imapclient.Client, newMailCh <-chan struct{}) error {
	idleCmd, err := c.Idle()
	if err != nil {
		return fmt.Errorf("IDLE: %w", err)
	}

	// RFC 2177: re-issue IDLE at least every 29 minutes so NAT gateways and
	// network middleboxes don't silently drop the idle TCP connection.
	keepalive := time.NewTicker(20 * time.Minute)
	defer keepalive.Stop()

	for {
		select {
		case <-ctx.Done():
			idleCmd.Close() //nolint:errcheck
			return nil

		case <-newMailCh:
			keepalive.Reset(20 * time.Minute)
			if err := idleCmd.Close(); err != nil {
				return fmt.Errorf("close IDLE: %w", err)
			}
			if err := l.fetchUnseen(ctx, c); err != nil {
				l.log.Warn("fetchUnseen after IDLE notify failed", "account", l.account.Name, "err", err)
			}
			idleCmd, err = c.Idle()
			if err != nil {
				return fmt.Errorf("restart IDLE: %w", err)
			}

		case <-keepalive.C:
			if err := idleCmd.Close(); err != nil {
				return fmt.Errorf("close IDLE for keepalive: %w", err)
			}
			idleCmd, err = c.Idle()
			if err != nil {
				return fmt.Errorf("restart IDLE after keepalive: %w", err)
			}
			l.log.Debug("IDLE keepalive", "account", l.account.Name)
		}
	}
}

// fetchUnseen searches for UNSEEN messages and dispatches each one. It loops
// until SEARCH UNSEEN returns zero results, so messages that arrive while a
// FETCH is in flight are not missed before the caller re-enters IDLE.
// Uses l.inFlight (listener-scoped) so dedup persists across consecutive
// fetchUnseen calls within the same connection — e.g. the connect-time fetch
// and a subsequent IDLE-triggered fetch (F-029, F-055).
func (l *Listener) fetchUnseen(ctx context.Context, c *imapclient.Client) error {
	for {
		if ctx.Err() != nil {
			return nil
		}

		// Drain \Seen completions before searching so the next SEARCH UNSEEN
		// reflects messages that finished processing in the previous iteration.
		l.drainSeen(c)
		// Remove drained UIDs from the listener-scoped in-flight set.
		for {
			select {
			case uid := <-l.seenConfirmCh:
				delete(l.inFlight, uid)
			default:
				goto drained
			}
		}
	drained:

		criteria := &imap.SearchCriteria{
			NotFlag: []imap.Flag{imap.FlagSeen},
		}
		// UID SEARCH returns UIDs directly — stable identifiers unaffected by EXPUNGE.
		// Using sequence numbers here would break dedup because seq nums shift when
		// messages are expunged, causing l.inFlight (keyed by UID) misses (F-055).
		searchData, err := c.UIDSearch(criteria, nil).Wait()
		if err != nil {
			return fmt.Errorf("SEARCH UNSEEN: %w", err)
		}
		allUIDs := searchData.AllUIDs()
		// Pre-filter: skip UIDs already in-flight to avoid re-fetching message bodies.
		newUIDs := allUIDs[:0]
		for _, uid := range allUIDs {
			if _, active := l.inFlight[uint32(uid)]; !active {
				newUIDs = append(newUIDs, uid)
			}
		}
		if len(newUIDs) == 0 {
			return nil
		}

		uidSet := imap.UIDSetNum(newUIDs...)
		fetchOptions := &imap.FetchOptions{
			UID: true,
			// Peek: true — do NOT auto-mark \Seen on FETCH. We mark \Seen explicitly
			// via drainSeen() after onEmail returns, so a crash before processing
			// completes leaves the message UNSEEN and eligible for retry.
			BodySection: []*imap.FetchItemBodySection{{Peek: true}},
		}

		messages, err := c.Fetch(uidSet, fetchOptions).Collect()
		if err != nil {
			return fmt.Errorf("FETCH: %w", err)
		}

		for _, msg := range messages {
			uid := uint32(msg.UID)
			var raw []byte
			for _, section := range msg.BodySection {
				raw = section.Bytes
				break
			}
			if len(raw) == 0 {
				l.log.Warn("empty message body", "account", l.account.Name, "uid", uid)
				continue
			}

			// Secondary dedup: guard against servers that return extra UIDs in a
			// UID FETCH response (should not happen, but defensive).
			if _, active := l.inFlight[uid]; active {
				continue
			}
			l.inFlight[uid] = struct{}{}

			// Block until a dispatch slot is free or context is cancelled.
			// Limits how many goroutines are queued at the pipeline semaphore,
			// preventing memory exhaustion when connecting to a large existing inbox.
			select {
			case l.dispatchSem <- struct{}{}:
			case <-ctx.Done():
				return nil
			}

			l.log.Debug("dispatching message", "account", l.account.Name, "uid", uid)
			go func(raw []byte, uid uint32) {
				defer func() { <-l.dispatchSem }()
				l.onEmail(ctx, l.account.Name, raw, uid, l.account.Mailbox)
				// Signal that this UID is fully processed and ready to be marked \Seen.
				// Non-blocking: if the buffer is full the mark is deferred to the next
				// drain cycle rather than blocking the goroutine.
				select {
				case l.seenCh <- uid:
				default:
					l.log.Warn("seenCh full — \\Seen mark deferred to next poll cycle",
						"account", l.account.Name, "uid", uid)
				}
				// Remove from in-flight tracking (best-effort, non-blocking).
				select {
				case l.seenConfirmCh <- uid:
				default:
				}
			}(raw, uid)
		}
		// Loop: re-search to catch messages that arrived during the fetch.
	}
}

// drainSeen pulls all pending UIDs from seenCh and issues a single batch
// UID STORE +FLAGS \Seen command. Must be called from the goroutine that owns
// the IMAP connection c.
func (l *Listener) drainSeen(c *imapclient.Client) {
	var uids []imap.UID
loop:
	for {
		select {
		case uid := <-l.seenCh:
			uids = append(uids, imap.UID(uid))
		default:
			break loop
		}
	}
	if len(uids) == 0 {
		return
	}
	uidSet := imap.UIDSetNum(uids...)
	storeData := &imap.StoreFlags{
		Op:     imap.StoreFlagsAdd,
		Flags:  []imap.Flag{imap.FlagSeen},
		Silent: true,
	}
	if err := c.Store(uidSet, storeData, nil).Close(); err != nil {
		l.log.Warn("batch \\Seen store failed", "account", l.account.Name, "err", err)
	}
}

func (l *Listener) dial(opts *imapclient.Options) (*imapclient.Client, error) {
	addr := fmt.Sprintf("%s:%d", l.account.Host, l.account.Port)
	if l.account.TLSSkipVerify {
		l.log.Warn("TLS certificate verification disabled — susceptible to MITM attacks; enable verification in account settings",
			"account", l.account.Name, "host", l.account.Host)
	}
	tlsCfg := &tls.Config{
		ServerName:         l.account.Host,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: l.account.TLSSkipVerify, // #nosec G402 -- per-account opt-in (TLSSkipVerify); MITM risk warned in logs
	}

	conn, err := tls.Dial("tcp", addr, tlsCfg)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}

	c := imapclient.New(conn, opts)

	if err := c.Login(l.account.User, l.account.Pass).Wait(); err != nil {
		c.Close()
		return nil, fmt.Errorf("login: %w", err)
	}

	return c, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
