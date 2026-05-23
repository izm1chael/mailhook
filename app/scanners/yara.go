package scanners

import (
	"context"
	"encoding/json"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/hillu/go-yara/v4"
	"github.com/izm1chael/mailhook/pipeline"
)

// YARA scans email raw bytes and attachment bytes against a compiled rule set.
// Rules are hot-reloaded when .yar files in rulesDir change.
type YARA struct {
	mu         sync.RWMutex
	rules      *yara.Rules // nil if no rules are loaded (valid empty state)
	ruleCount  int
	lastLoaded time.Time
	rulesDir   string
	log        *slog.Logger

	enabledMu sync.RWMutex
	enabled   bool
}

// NewYARA creates a YARA scanner and compiles all .yar files in rulesDir.
// Returns no error if rulesDir is empty — an empty rule set is valid.
func NewYARA(rulesDir string, log *slog.Logger) (*YARA, error) {
	y := &YARA{rulesDir: rulesDir, log: log, enabled: true}
	if err := y.loadRules(); err != nil {
		return nil, err
	}
	return y, nil
}

// SetEnabled enables or disables the scanner at runtime.
func (y *YARA) SetEnabled(v bool) { y.enabledMu.Lock(); y.enabled = v; y.enabledMu.Unlock() }

// IsEnabled reports whether the scanner is currently enabled.
func (y *YARA) IsEnabled() bool { y.enabledMu.RLock(); defer y.enabledMu.RUnlock(); return y.enabled }

func (y *YARA) Name() string { return "yara" }

// Scan runs the compiled rules against the full raw message and each attachment.
func (y *YARA) Scan(ctx context.Context, email *pipeline.Email) pipeline.ScanResult {
	y.enabledMu.RLock()
	enabled := y.enabled
	y.enabledMu.RUnlock()
	if !enabled {
		return pipeline.ScanResult{Scanner: y.Name(), Verdict: "skip", Detail: "disabled"}
	}

	y.mu.RLock()
	rules := y.rules
	y.mu.RUnlock()

	if rules == nil {
		// No rules compiled — scanner is disabled, not failed. Return clean so
		// the fail-closed verdict logic (which only triggers on "error") is not
		// tripped for intentionally unconfigured deployments.
		return pipeline.ScanResult{Scanner: y.Name(), Verdict: "clean", Detail: "no rules loaded"}
	}

	// Derive scan timeout from the context deadline so a slow scan cannot exceed
	// the pipeline's per-stage budget. A floor of 500ms prevents the timeout from
	// being set so low that YARA can't complete even a trivial scan, which would
	// cause fail-closed quarantine of clean mail under load.
	const yaraMinTimeout = 500 * time.Millisecond
	scanTimeout := 8 * time.Second
	if dl, ok := ctx.Deadline(); ok {
		if rem := time.Until(dl) - 50*time.Millisecond; rem > 0 && rem < scanTimeout {
			if rem < yaraMinTimeout {
				rem = yaraMinTimeout
			}
			scanTimeout = rem
		}
	}

	var matched []string

	// Scan full raw message
	cb := &matchCollector{}
	if err := rules.ScanMem(email.Raw, 0, scanTimeout, cb); err != nil {
		y.log.Warn("yara scan error on message body", "err", err)
		return pipeline.ScanResult{Scanner: y.Name(), Verdict: "error", Detail: err.Error()}
	}
	matched = append(matched, cb.names...)

	// Scan each attachment
	for _, att := range email.Attachments {
		if len(att.Raw) == 0 {
			continue
		}
		attCB := &matchCollector{}
		if err := rules.ScanMem(att.Raw, 0, scanTimeout, attCB); err != nil {
			y.log.Warn("yara scan error on attachment", "filename", att.Filename, "err", err)
			return pipeline.ScanResult{Scanner: y.Name(), Verdict: "error", Detail: err.Error()}
		}
		matched = append(matched, attCB.names...)
	}

	if len(matched) == 0 {
		return pipeline.ScanResult{Scanner: y.Name(), Verdict: "clean"}
	}

	dedup := uniqueStrings(matched)
	matchData, _ := json.Marshal(dedup)
	return pipeline.ScanResult{
		Scanner: y.Name(),
		Verdict: "malicious",
		Detail:  strings.Join(dedup, ", "),
		Matches: matchData,
	}
}

// ReloadRules recompiles all .yar files from disk immediately.
// Used by the settings API to hot-reload rules without waiting for file-change events.
func (y *YARA) ReloadRules() error {
	return y.loadRules()
}

// SetRulesDir changes the rules directory and reloads rules immediately.
func (y *YARA) SetRulesDir(dir string) error {
	y.mu.Lock()
	y.rulesDir = dir
	y.mu.Unlock()
	return y.loadRules()
}

// WatchRules starts a file watcher that recompiles rules when .yar files change.
// Blocks until ctx is cancelled. Call in a goroutine.
//
// A 30-second polling fallback supplements the inotify watcher. On Docker Desktop
// (Mac/Windows) with bind-mounted rules directories, host-side file changes rarely
// produce Linux inotify events inside the container. The poll catches these missed
// events so hot-reload works regardless of the hypervisor layer.
func (y *YARA) WatchRules(ctx context.Context) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		y.log.Warn("yara hot-reload watcher failed", "err", err)
		return
	}
	defer watcher.Close()

	// Watch the rules dir and all subdirectories so nested .yar changes fire events.
	// filepath.WalkDir is the same recursive walk loadRules uses.
	addWatchDirs := func(dir string) {
		filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error { //nolint:errcheck
			if err == nil && d.IsDir() {
				if werr := watcher.Add(path); werr != nil {
					y.log.Warn("yara watcher cannot watch dir", "dir", path, "err", werr)
				}
			}
			return nil
		})
	}
	addWatchDirs(y.rulesDir)

	debounce := time.NewTimer(0)
	<-debounce.C // drain the initial fire

	pollTicker := time.NewTicker(30 * time.Second)
	defer pollTicker.Stop()

	lastModTimes := y.ruleModTimes()

	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			if strings.HasSuffix(event.Name, ".yar") &&
				(event.Has(fsnotify.Write) || event.Has(fsnotify.Create) || event.Has(fsnotify.Remove)) {
				debounce.Reset(2 * time.Second)
			}

		case <-pollTicker.C:
			// Fallback for Docker Desktop bind mounts where inotify events are not delivered.
			current := y.ruleModTimes()
			if !ruleModTimesEqual(lastModTimes, current) {
				lastModTimes = current
				debounce.Reset(2 * time.Second)
			}

		case <-debounce.C:
			y.log.Info("yara rules changed, reloading")
			if err := y.loadRules(); err != nil {
				y.log.Error("yara rule reload failed", "err", err)
			} else {
				y.mu.RLock()
				n := y.ruleCount
				y.mu.RUnlock()
				y.log.Info("yara rules reloaded", "rules", n)
			}
			lastModTimes = y.ruleModTimes()

		case err := <-watcher.Errors:
			y.log.Warn("yara watcher error", "err", err)

		case <-ctx.Done():
			return
		}
	}
}

// ruleModTimes returns a snapshot of ModTime for every .yar file in rulesDir.
func (y *YARA) ruleModTimes() map[string]time.Time {
	y.mu.RLock()
	dir := y.rulesDir
	y.mu.RUnlock()

	times := make(map[string]time.Time)
	filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error { //nolint:errcheck
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".yar") {
			return nil
		}
		if info, err := d.Info(); err == nil {
			times[path] = info.ModTime()
		}
		return nil
	})
	return times
}

// ruleModTimesEqual reports whether two ModTime snapshots are identical.
func ruleModTimesEqual(a, b map[string]time.Time) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if bv, ok := b[k]; !ok || !v.Equal(bv) {
			return false
		}
	}
	return true
}

func (y *YARA) loadRules() error {
	compiler, err := yara.NewCompiler()
	if err != nil {
		return err
	}
	// compiler.Destroy() frees C-heap memory the Go GC cannot see. Safe to call
	// after GetRules() — the compiled *yara.Rules owns its own independent C memory.
	defer compiler.Destroy()

	var count int
	err = filepath.WalkDir(y.rulesDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".yar") {
			return nil
		}
		f, err := os.Open(path) // #nosec G304 G122 -- path is a .yar file under the operator-configured rulesDir, not attacker-controlled
		if err != nil {
			y.log.Warn("yara: cannot open rule file", "path", path, "err", err)
			return nil
		}
		defer f.Close()

		namespace := strings.TrimSuffix(filepath.Base(path), ".yar")
		if err := compiler.AddFile(f, namespace); err != nil {
			y.log.Warn("yara: rule compile error", "path", path, "err", err)
			return nil
		}
		count++
		return nil
	})
	if err != nil {
		return err
	}

	if count == 0 {
		y.mu.Lock()
		y.rules = nil
		y.ruleCount = 0
		y.lastLoaded = time.Now()
		y.mu.Unlock()
		return nil
	}

	rules, err := compiler.GetRules()
	if err != nil {
		return err
	}

	// Count individual rules in the compiled set
	compiled := rules.GetRules()

	y.mu.Lock()
	old := y.rules
	y.rules = rules
	y.ruleCount = len(compiled)
	y.lastLoaded = time.Now()
	y.mu.Unlock()

	// Destroy the previous compiled ruleset after a delay that exceeds the maximum
	// YARA scan timeout (8s). Any goroutine that captured old under the read lock
	// will have finished scanning before the delay expires.
	if old != nil {
		go func() {
			time.Sleep(10 * time.Second)
			old.Destroy()
		}()
	}

	y.log.Info("yara rules loaded", "file_count", count, "rule_count", len(compiled))
	return nil
}

// RuleCount returns the number of compiled YARA rules currently loaded.
func (y *YARA) RuleCount() int {
	y.mu.RLock()
	defer y.mu.RUnlock()
	return y.ruleCount
}

// LastLoaded returns when the YARA rules were last compiled.
func (y *YARA) LastLoaded() time.Time {
	y.mu.RLock()
	defer y.mu.RUnlock()
	return y.lastLoaded
}

// matchCollector implements yara.ScanCallback and collects matched rule identifiers.
type matchCollector struct {
	names []string
}

func (m *matchCollector) RuleMatching(_ *yara.ScanContext, r *yara.Rule) (bool, error) {
	m.names = append(m.names, r.Identifier())
	return false, nil
}

func uniqueStrings(ss []string) []string {
	seen := make(map[string]bool, len(ss))
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
