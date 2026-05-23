package feeds

import (
	"testing"
)

func TestParsePhishTankJSON_Pretty(t *testing.T) {
	input := `[
  {
    "url": "http://phish1.example/login",
    "verified": true
  },
  {
    "url": "http://phish2.example/steal",
    "verified": false
  },
  {
    "url": "http://phish3.example/hook",
    "verified": true
  }
]`
	urls, err := parsePhishTankJSON([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(urls) != 2 {
		t.Fatalf("got %d urls, want 2", len(urls))
	}
	if urls[0] != "http://phish1.example/login" {
		t.Errorf("urls[0] = %q, want http://phish1.example/login", urls[0])
	}
	if urls[1] != "http://phish3.example/hook" {
		t.Errorf("urls[1] = %q, want http://phish3.example/hook", urls[1])
	}
}

func TestParsePhishTankJSON_Compact(t *testing.T) {
	// Compact JSON on a single line — the old line-scanner approach would miss this.
	input := `[{"url":"http://compact1.example/","verified":true},{"url":"http://compact2.example/","verified":false},{"url":"http://compact3.example/","verified":true}]`
	urls, err := parsePhishTankJSON([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(urls) != 2 {
		t.Fatalf("got %d urls, want 2", len(urls))
	}
}

func TestParsePhishTankJSON_Empty(t *testing.T) {
	urls, err := parsePhishTankJSON([]byte(`[]`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(urls) != 0 {
		t.Errorf("got %d urls, want 0", len(urls))
	}
}

func TestParsePhishTankJSON_NotAnArray(t *testing.T) {
	_, err := parsePhishTankJSON([]byte(`{"url":"not-an-array"}`))
	if err == nil {
		t.Error("expected error for non-array JSON, got nil")
	}
}

func TestParsePhishTankJSON_MalformedJSON(t *testing.T) {
	_, err := parsePhishTankJSON([]byte(`[{bad json`))
	if err == nil {
		t.Error("expected error for malformed JSON, got nil")
	}
}

func TestParsePhishTankJSON_SkipsUnverified(t *testing.T) {
	// None of these are verified — result should be empty.
	input := `[
    {"url":"http://a.example/","verified":false},
    {"url":"http://b.example/","verified":false}
  ]`
	urls, err := parsePhishTankJSON([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(urls) != 0 {
		t.Errorf("expected 0 urls (all unverified), got %d", len(urls))
	}
}
