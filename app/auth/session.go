package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"

	"github.com/izm1chael/mailhook/db"
	"gorm.io/gorm"
)

// Session represents an authenticated web session.
type Session struct {
	Token      string
	Username   string
	IPAddr     string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	LastSeenAt time.Time
}

// Store manages in-memory sessions with optional DB persistence across restarts.
type Store struct {
	mu       sync.Mutex
	sessions map[string]*Session
	ttl      time.Duration
}

const defaultIdleTimeout = 4 * time.Hour

// NewStore creates a session store with the given session lifetime.
func NewStore(ttl time.Duration) *Store {
	return &Store{
		sessions: make(map[string]*Session),
		ttl:      ttl,
	}
}

// Create generates a new session for username from the given IP address.
// Returns the session token to set as a cookie.
func (s *Store) Create(username, ip string) string {
	token := generateToken()
	now := time.Now()
	sess := &Session{
		Token:      token,
		Username:   username,
		IPAddr:     ip,
		CreatedAt:  now,
		ExpiresAt:  now.Add(s.ttl),
		LastSeenAt: now,
	}
	s.mu.Lock()
	s.sessions[token] = sess
	s.mu.Unlock()
	return token
}

// Get returns the session for the given token if it exists and has not expired or gone idle.
func (s *Store) Get(token string) (*Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[token]
	if !ok {
		return nil, false
	}
	now := time.Now()
	if now.After(sess.ExpiresAt) || now.Sub(sess.LastSeenAt) > defaultIdleTimeout {
		delete(s.sessions, token)
		return nil, false
	}
	return sess, true
}

// Touch updates the LastSeenAt timestamp for the session, preventing idle expiry.
func (s *Store) Touch(token string) {
	s.mu.Lock()
	if sess, ok := s.sessions[token]; ok {
		sess.LastSeenAt = time.Now()
	}
	s.mu.Unlock()
}

// DeleteAll removes all active sessions. Call after a password change to force re-login.
func (s *Store) DeleteAll() {
	s.mu.Lock()
	s.sessions = make(map[string]*Session)
	s.mu.Unlock()
}

// Delete removes the session (logout).
func (s *Store) Delete(token string) {
	s.mu.Lock()
	delete(s.sessions, token)
	s.mu.Unlock()
}

// Sweep removes all expired and idle sessions. Call periodically (e.g. every hour).
func (s *Store) Sweep() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for token, sess := range s.sessions {
		if now.After(sess.ExpiresAt) || now.Sub(sess.LastSeenAt) > defaultIdleTimeout {
			delete(s.sessions, token)
		}
	}
}

// TTL returns the configured session lifetime.
func (s *Store) TTL() time.Duration { return s.ttl }

// SweepLoop runs Sweep on a ticker until ctx is cancelled.
func (s *Store) SweepLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.Sweep()
		case <-ctx.Done():
			return
		}
	}
}

// PersistToDB saves all unexpired sessions to the database.
func (s *Store) PersistToDB(gdb *db.DB) error {
	s.mu.Lock()
	var valid []db.Session
	now := time.Now()
	for _, sess := range s.sessions {
		if now.Before(sess.ExpiresAt) {
			valid = append(valid, db.Session{
				Token:     sess.Token,
				Username:  sess.Username,
				IPAddr:    sess.IPAddr,
				CreatedAt: sess.CreatedAt,
				ExpiresAt: sess.ExpiresAt,
			})
		}
	}
	s.mu.Unlock()
	return gdb.Write(func(tx *gorm.DB) error {
		tx.Where("1 = 1").Delete(&db.Session{})
		if len(valid) > 0 {
			return tx.CreateInBatches(valid, 100).Error
		}
		return nil
	})
}

// LoadFromDB restores unexpired sessions from the database on startup.
func (s *Store) LoadFromDB(gdb *db.DB) {
	var dbSessions []db.Session
	gdb.Where("expires_at > ?", time.Now()).Find(&dbSessions)

	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for _, dbs := range dbSessions {
		s.sessions[dbs.Token] = &Session{
			Token:      dbs.Token,
			Username:   dbs.Username,
			IPAddr:     dbs.IPAddr,
			CreatedAt:  dbs.CreatedAt,
			ExpiresAt:  dbs.ExpiresAt,
			LastSeenAt: now,
		}
	}
}

func generateToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("auth: crypto/rand unavailable: " + err.Error())
	}
	return hex.EncodeToString(b)
}
