package handlers

import (
	"testing"
)

func TestDetectEntryType(t *testing.T) {
	valid := []struct {
		entry string
		want  string
	}{
		{"user@example.com", "address"},
		{"admin@sub.example.com", "address"},
		{"@example.com", "domain"},
		{"@sub.example.com", "domain"},
		{"example.com", "domain"},
	}
	for _, tc := range valid {
		got, err := detectEntryType(tc.entry)
		if err != nil {
			t.Errorf("detectEntryType(%q) unexpected error: %v", tc.entry, err)
			continue
		}
		if got != tc.want {
			t.Errorf("detectEntryType(%q) = %q, want %q", tc.entry, got, tc.want)
		}
	}

	invalid := []string{
		"notanemail",        // no dot, not a valid domain or email
		"spaces in it",     // whitespace
		"http://bad.com",   // scheme prefix
		"@",                // bare @ only
	}
	for _, entry := range invalid {
		_, err := detectEntryType(entry)
		if err == nil {
			t.Errorf("detectEntryType(%q) expected error, got nil", entry)
		}
	}
}
