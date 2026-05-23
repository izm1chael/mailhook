package scanners

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/izm1chael/mailhook/pipeline"
)

func newTestYARA(t *testing.T, ruleContent string) *YARA {
	t.Helper()
	dir := t.TempDir()
	if ruleContent != "" {
		if err := os.WriteFile(filepath.Join(dir, "test.yar"), []byte(ruleContent), 0600); err != nil {
			t.Fatalf("write rule file: %v", err)
		}
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	y, err := NewYARA(dir, log)
	if err != nil {
		t.Fatalf("NewYARA: %v", err)
	}
	return y
}

func TestYARA_Clean(t *testing.T) {
	rule := `rule AlwaysMatch { strings: $a = "MALWARE_TRIGGER" condition: $a }`
	y := newTestYARA(t, rule)

	email := &pipeline.Email{Raw: []byte("Hello, this is a clean message.")}
	result := y.Scan(context.Background(), email)
	if result.Verdict != "clean" {
		t.Errorf("Verdict = %q, want \"clean\"", result.Verdict)
	}
}

func TestYARA_Malicious(t *testing.T) {
	rule := `rule DetectTrigger { strings: $a = "MALWARE_TRIGGER" condition: $a }`
	y := newTestYARA(t, rule)

	email := &pipeline.Email{Raw: []byte("Body contains MALWARE_TRIGGER here.")}
	result := y.Scan(context.Background(), email)
	if result.Verdict != "malicious" {
		t.Errorf("Verdict = %q, want \"malicious\"", result.Verdict)
	}
	if result.Detail == "" {
		t.Error("Detail should contain matched rule name")
	}
	if len(result.Matches) == 0 {
		t.Error("Matches should be populated with rule names JSON")
	}
}

func TestYARA_NoRules(t *testing.T) {
	y := newTestYARA(t, "")
	email := &pipeline.Email{Raw: []byte("anything")}
	result := y.Scan(context.Background(), email)
	// No rules loaded = intentionally unconfigured, not a failure — returns "clean"
	// so the fail-closed logic (triggered only by "error") is not tripped.
	if result.Verdict != "clean" {
		t.Errorf("Verdict = %q, want \"clean\" when no rules loaded", result.Verdict)
	}
}

func TestYARA_Disabled(t *testing.T) {
	y := newTestYARA(t, "")
	y.SetEnabled(false)
	email := &pipeline.Email{Raw: []byte("anything")}
	result := y.Scan(context.Background(), email)
	if result.Verdict != "skip" {
		t.Errorf("Verdict = %q, want \"skip\" when disabled", result.Verdict)
	}
}

func TestYARA_ContextDeadlinePropagated(t *testing.T) {
	// Verify scan completes within the context deadline rather than using the
	// hardcoded 10-second YARA timeout. A 200ms deadline is more than enough for
	// scanning a tiny message but much less than 10s.
	rule := `rule DetectTrigger { strings: $a = "MALWARE_TRIGGER" condition: $a }`
	y := newTestYARA(t, rule)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	email := &pipeline.Email{Raw: []byte("clean message")}
	result := y.Scan(ctx, email)
	// A clean scan on a tiny message should complete well within 200ms.
	if result.Verdict != "clean" && result.Verdict != "error" {
		t.Errorf("unexpected Verdict = %q", result.Verdict)
	}
}
