package imap

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"sync"

	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/izm1chael/mailhook/config"
	"github.com/izm1chael/mailhook/db"
)

// Manager tracks live IMAP listeners and provides add/remove/restart without process restart.
type Manager struct {
	mu        sync.RWMutex
	cancels   map[string]context.CancelFunc
	parentCtx context.Context
	gdb       *db.DB
	log       *slog.Logger
}

// NewManager returns a Manager whose per-account goroutines are children of parentCtx.
func NewManager(parentCtx context.Context, gdb *db.DB, log *slog.Logger) *Manager {
	return &Manager{
		cancels:   make(map[string]context.CancelFunc),
		parentCtx: parentCtx,
		gdb:       gdb,
		log:       log,
	}
}

// Start launches listener + recovery goroutines for account. Returns error if already running.
func (m *Manager) Start(account config.AccountConfig, onEmail OnEmailFn) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.cancels[account.Name]; exists {
		return fmt.Errorf("account %q already running", account.Name)
	}
	ctx, cancel := context.WithCancel(m.parentCtx) // #nosec G118 -- cancel is retained in m.cancels and invoked by Stop()
	m.cancels[account.Name] = cancel

	go NewListener(account, onEmail, m.log).Run(ctx)
	go NewRecovery(account, m.gdb, onEmail, m.log).Run(ctx)
	return nil
}

// Stop cancels goroutines for the named account. No-op if not running.
func (m *Manager) Stop(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if cancel, ok := m.cancels[name]; ok {
		cancel()
		delete(m.cancels, name)
	}
}

// Restart stops then starts an account listener with potentially updated config.
func (m *Manager) Restart(account config.AccountConfig, onEmail OnEmailFn) error {
	m.Stop(account.Name)
	return m.Start(account, onEmail)
}

// IsRunning reports whether the named account has active goroutines.
func (m *Manager) IsRunning(name string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.cancels[name]
	return ok
}

// Test dials the IMAP server and attempts authentication to verify credentials.
// Returns nil on success.
func (m *Manager) Test(ctx context.Context, account config.AccountConfig) error {
	addr := fmt.Sprintf("%s:%d", account.Host, account.Port)
	c, err := imapclient.DialTLS(addr, &imapclient.Options{
		TLSConfig: &tls.Config{
			ServerName:         account.Host,
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: account.TLSSkipVerify, // #nosec G402 -- per-account opt-in (TLSSkipVerify); MITM risk warned in logs
		},
	})
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer c.Close()
	if err := c.Login(account.User, account.Pass).Wait(); err != nil {
		return fmt.Errorf("login: %w", err)
	}
	return nil
}
