package util

import (
	"strings"
	"testing"
)

func TestSHA256Hex(t *testing.T) {
	// Known SHA-256 of empty string
	got := SHA256Hex([]byte(""))
	want := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if got != want {
		t.Errorf("SHA256Hex(\"\") = %q, want %q", got, want)
	}

	// Known SHA-256 of "hello"
	got2 := SHA256Hex([]byte("hello"))
	want2 := "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	if got2 != want2 {
		t.Errorf("SHA256Hex(\"hello\") = %q, want %q", got2, want2)
	}

	// Should be lowercase hex
	if got != strings.ToLower(got) {
		t.Errorf("SHA256Hex result not lowercase: %q", got)
	}
	// Should be 64 chars
	if len(got) != 64 {
		t.Errorf("SHA256Hex result wrong length: %d", len(got))
	}
}
