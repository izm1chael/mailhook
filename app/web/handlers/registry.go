package handlers

import "sync"

// AccountRegistry is a thread-safe mapping from account name to its IMAP action
// handler and email processor. It is the single source of truth for live accounts
// throughout the process lifetime: populated at startup and updated atomically
// whenever an account is created, updated, or deleted via the Settings UI.
type AccountRegistry struct {
	mu         sync.RWMutex
	actions    map[string]IMAPActions
	processors map[string]EmailProcessor
}

// NewAccountRegistry creates an empty registry.
func NewAccountRegistry() *AccountRegistry {
	return &AccountRegistry{
		actions:    make(map[string]IMAPActions),
		processors: make(map[string]EmailProcessor),
	}
}

// Add registers (or replaces) an account's action handler and processor.
// Safe to call concurrently.
func (r *AccountRegistry) Add(name string, act IMAPActions, proc EmailProcessor) {
	r.mu.Lock()
	r.actions[name] = act
	r.processors[name] = proc
	r.mu.Unlock()
}

// Remove deletes an account from the registry.
// Safe to call concurrently.
func (r *AccountRegistry) Remove(name string) {
	r.mu.Lock()
	delete(r.actions, name)
	delete(r.processors, name)
	r.mu.Unlock()
}

// GetActions returns the IMAPActions for the named account and whether it was found.
func (r *AccountRegistry) GetActions(name string) (IMAPActions, bool) {
	r.mu.RLock()
	act, ok := r.actions[name]
	r.mu.RUnlock()
	return act, ok
}

// GetProcessor returns the EmailProcessor for the named account and whether it was found.
func (r *AccountRegistry) GetProcessor(name string) (EmailProcessor, bool) {
	r.mu.RLock()
	proc, ok := r.processors[name]
	r.mu.RUnlock()
	return proc, ok
}
