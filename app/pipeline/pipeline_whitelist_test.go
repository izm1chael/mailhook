package pipeline

import (
	"testing"
)

// TestListCandidates_DisplayName verifies that RFC 5322 display-name addresses
// (as produced by net/mail.Address.String()) yield bare addresses without angle
// brackets, matching how entries are stored in the allow/blocklist tables.
func TestListCandidates_DisplayName(t *testing.T) {
	// Simulate what email.go sets: from[0].String() on a parsed address.
	email := &Email{From: `"Alice Smith" <Alice@Example.COM>`}
	candidates := listCandidates(email)

	if len(candidates) != 2 {
		t.Fatalf("expected exactly 2 candidates, got %d: %v", len(candidates), candidates)
	}
	if candidates[0] != "alice@example.com" {
		t.Errorf("candidates[0] = %q, want %q", candidates[0], "alice@example.com")
	}
	if candidates[1] != "@example.com" {
		t.Errorf("candidates[1] = %q, want %q", candidates[1], "@example.com")
	}
	for _, c := range candidates {
		for _, ch := range c {
			if ch >= 'A' && ch <= 'Z' {
				t.Errorf("candidate %q contains uppercase", c)
			}
		}
	}
}

func TestListCandidates_BareDomain(t *testing.T) {
	email := &Email{From: "sender@example.com"}
	candidates := listCandidates(email)

	if len(candidates) != 2 {
		t.Fatalf("expected exactly 2 candidates, got %d: %v", len(candidates), candidates)
	}
	if candidates[0] != "sender@example.com" {
		t.Errorf("candidates[0] = %q, want %q", candidates[0], "sender@example.com")
	}
	if candidates[1] != "@example.com" {
		t.Errorf("candidates[1] = %q, want %q", candidates[1], "@example.com")
	}
}

// TestListCandidates_AngleBracketOnly verifies angle-bracket-only format is handled.
func TestListCandidates_AngleBracketOnly(t *testing.T) {
	email := &Email{From: "<alice@example.com>"}
	candidates := listCandidates(email)
	if len(candidates) != 2 {
		t.Fatalf("expected 2 candidates, got %d: %v", len(candidates), candidates)
	}
	if candidates[0] != "alice@example.com" {
		t.Errorf("candidates[0] = %q, want %q", candidates[0], "alice@example.com")
	}
}

func TestListCandidates_NoAt(t *testing.T) {
	// Malformed From with no @ should not panic, just return single candidate
	email := &Email{From: "notanemail"}
	candidates := listCandidates(email)
	if len(candidates) == 0 {
		t.Error("expected at least one candidate")
	}
}

func TestSenderAuthAligned_PassPassPass(t *testing.T) {
	email := &Email{SPFResult: "pass", DKIMResult: "pass", DMARCResult: "pass"}
	if !senderAuthAligned(email) {
		t.Error("expected aligned with SPF+DKIM+DMARC pass")
	}
}

func TestSenderAuthAligned_SPFOnlyNotEnough(t *testing.T) {
	// SPF pass alone without DKIM or DMARC is not enough.
	email := &Email{SPFResult: "pass", DKIMResult: "fail", DMARCResult: "fail"}
	if senderAuthAligned(email) {
		t.Error("SPF-only should not be considered aligned (requires DKIM or DMARC too)")
	}
}

func TestSenderAuthAligned_SPFPlusDKIM(t *testing.T) {
	email := &Email{SPFResult: "pass", DKIMResult: "pass", DMARCResult: "none"}
	if !senderAuthAligned(email) {
		t.Error("expected aligned with SPF+DKIM pass")
	}
}

func TestSenderAuthAligned_SPFPlusDMARC(t *testing.T) {
	email := &Email{SPFResult: "pass", DKIMResult: "none", DMARCResult: "pass"}
	if !senderAuthAligned(email) {
		t.Error("expected aligned with SPF+DMARC pass")
	}
}

func TestSenderAuthAligned_Fail(t *testing.T) {
	email := &Email{SPFResult: "fail", DKIMResult: "fail", DMARCResult: "fail"}
	if senderAuthAligned(email) {
		t.Error("expected not aligned with all fail")
	}
}
