package scanners

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/izm1chael/mailhook/config"
	"github.com/izm1chael/mailhook/db"
	"github.com/izm1chael/mailhook/pipeline"
)

func newHTMLSmugglingScanner(t *testing.T, enabled bool, minB64KB int) *HTMLSmuggling {
	t.Helper()
	return NewHTMLSmuggling(&config.Config{
		HTMLSmugglingEnabled:  enabled,
		HTMLSmugglingMinB64KB: minB64KB,
	}, newTestLogger())
}

// largeB64 returns a base64-like string of approximately sizeKB kilobytes.
// Uses only characters valid in the b64ChunkRe pattern.
func largeB64(sizeKB int) string {
	// 1 KB of binary ≈ 1365 base64 chars; add 10% margin
	chars := sizeKB * 1024 * 4 / 3
	return strings.Repeat("A", chars+100)
}

// smallB64 returns a base64-like string well below the 10 KB threshold (200 chars).
func smallB64() string { return strings.Repeat("B", 500) }

func TestHTMLSmuggling_Disabled(t *testing.T) {
	s := newHTMLSmugglingScanner(t, false, 10)
	email := &pipeline.Email{HTMLBody: `<script>var d="` + largeB64(12) + `"; new Blob([d]);</script>`}
	res := s.Scan(context.Background(), email)
	if res.Verdict != "skip" {
		t.Fatalf("expected skip when disabled, got %s", res.Verdict)
	}
}

func TestHTMLSmuggling_NoHTMLBody(t *testing.T) {
	s := newHTMLSmugglingScanner(t, true, 10)
	email := &pipeline.Email{HTMLBody: ""}
	res := s.Scan(context.Background(), email)
	if res.Verdict != "clean" {
		t.Fatalf("expected clean for empty body, got %s", res.Verdict)
	}
}

func TestHTMLSmuggling_CleanHTML(t *testing.T) {
	s := newHTMLSmugglingScanner(t, true, 10)
	email := &pipeline.Email{HTMLBody: `<html><body><p>Hello world</p></body></html>`}
	res := s.Scan(context.Background(), email)
	if res.Verdict != "clean" {
		t.Fatalf("expected clean, got %s", res.Verdict)
	}
}

func TestHTMLSmuggling_LargeB64NoAPI_Clean(t *testing.T) {
	// Large base64 blob present but no Blob API → should NOT trigger (false-positive prevention)
	s := newHTMLSmugglingScanner(t, true, 10)
	b64 := largeB64(11)
	email := &pipeline.Email{HTMLBody: `<img src="data:image/png;base64,` + b64 + `">`}
	res := s.Scan(context.Background(), email)
	if res.Verdict != "clean" {
		t.Fatalf("large base64 alone (no Blob API) should be clean, got %s", res.Verdict)
	}
}

func TestHTMLSmuggling_BlobAPINoLargeB64_Clean(t *testing.T) {
	// Blob API present but base64 is below threshold → should NOT trigger
	s := newHTMLSmugglingScanner(t, true, 10)
	email := &pipeline.Email{HTMLBody: `<script>new Blob(["` + smallB64() + `"]);</script>`}
	res := s.Scan(context.Background(), email)
	if res.Verdict != "clean" {
		t.Fatalf("Blob API without large base64 should be clean, got %s", res.Verdict)
	}
}

func TestHTMLSmuggling_HTMLBody_NewBlob_Suspicious(t *testing.T) {
	s := newHTMLSmugglingScanner(t, true, 10)
	b64 := largeB64(11)
	html := `<html><body><script>var d="` + b64 + `"; var blob = new Blob([d]);</script></body></html>`
	email := &pipeline.Email{HTMLBody: html}
	res := s.Scan(context.Background(), email)
	if res.Verdict != "suspicious" {
		t.Fatalf("expected suspicious, got %s", res.Verdict)
	}
	if res.Score != 0.80 {
		t.Errorf("expected score 0.80, got %f", res.Score)
	}
	if !strings.Contains(res.Detail, "new Blob(") {
		t.Errorf("expected detail to mention 'new Blob(', got %q", res.Detail)
	}

	var hits []db.HTMLSmugglingHit
	if err := json.Unmarshal(res.Matches, &hits); err != nil {
		t.Fatalf("unmarshal hits: %v", err)
	}
	if len(hits) != 1 {
		t.Fatalf("expected 1 hit, got %d", len(hits))
	}
	if hits[0].Source != "body" {
		t.Errorf("expected source 'body', got %q", hits[0].Source)
	}
	if hits[0].B64SizeKB < 10 {
		t.Errorf("expected B64SizeKB >= 10, got %d", hits[0].B64SizeKB)
	}
}

func TestHTMLSmuggling_HTMLBody_msSaveOrOpenBlob_Suspicious(t *testing.T) {
	s := newHTMLSmugglingScanner(t, true, 10)
	b64 := largeB64(12)
	html := `<script>var d="` + b64 + `"; navigator.msSaveOrOpenBlob(blob,'file.zip');</script>`
	email := &pipeline.Email{HTMLBody: html}
	res := s.Scan(context.Background(), email)
	if res.Verdict != "suspicious" {
		t.Fatalf("expected suspicious for msSaveOrOpenBlob, got %s", res.Verdict)
	}

	var hits []db.HTMLSmugglingHit
	if err := json.Unmarshal(res.Matches, &hits); err != nil {
		t.Fatalf("unmarshal hits: %v", err)
	}
	found := false
	for _, api := range hits[0].BlobAPIs {
		if api == "msSaveOrOpenBlob" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected msSaveOrOpenBlob in blob_apis, got %v", hits[0].BlobAPIs)
	}
}

func TestHTMLSmuggling_HTMLBody_createObjectURL_Suspicious(t *testing.T) {
	s := newHTMLSmugglingScanner(t, true, 10)
	b64 := largeB64(11)
	html := `<script>var d="` + b64 + `"; var u=URL.createObjectURL(blob); a.href=u;</script>`
	email := &pipeline.Email{HTMLBody: html}
	res := s.Scan(context.Background(), email)
	if res.Verdict != "suspicious" {
		t.Fatalf("expected suspicious for createObjectURL, got %s", res.Verdict)
	}
}

func TestHTMLSmuggling_HTMLAttachment_Suspicious(t *testing.T) {
	s := newHTMLSmugglingScanner(t, true, 10)
	b64 := largeB64(11)
	attContent := []byte(`<html><script>var d="` + b64 + `"; new Blob([d]);</script></html>`)
	email := &pipeline.Email{
		Attachments: []pipeline.Attachment{
			{
				Filename:    "invoice.html",
				ContentType: "text/html",
				Extension:   ".html",
				Raw:         attContent,
			},
		},
	}
	res := s.Scan(context.Background(), email)
	if res.Verdict != "suspicious" {
		t.Fatalf("expected suspicious for HTML attachment, got %s", res.Verdict)
	}

	var hits []db.HTMLSmugglingHit
	if err := json.Unmarshal(res.Matches, &hits); err != nil {
		t.Fatalf("unmarshal hits: %v", err)
	}
	if hits[0].Source != "attachment:invoice.html" {
		t.Errorf("expected source 'attachment:invoice.html', got %q", hits[0].Source)
	}
}

func TestHTMLSmuggling_HTMLAttachmentByExtension_Suspicious(t *testing.T) {
	// Attachment detected by .htm extension (not content-type)
	s := newHTMLSmugglingScanner(t, true, 10)
	b64 := largeB64(11)
	attContent := []byte(`<html><script>var d="` + b64 + `"; saveAs(blob,'doc.zip');</script></html>`)
	email := &pipeline.Email{
		Attachments: []pipeline.Attachment{
			{
				Filename:    "doc.htm",
				ContentType: "application/octet-stream",
				Extension:   ".htm",
				Raw:         attContent,
			},
		},
	}
	res := s.Scan(context.Background(), email)
	if res.Verdict != "suspicious" {
		t.Fatalf("expected suspicious for .htm attachment, got %s", res.Verdict)
	}
}

func TestHTMLSmuggling_BelowThreshold_Clean(t *testing.T) {
	// Default threshold is 10KB; test with 5KB payload → clean
	s := newHTMLSmugglingScanner(t, true, 10)
	b64 := largeB64(5)
	html := `<script>var d="` + b64 + `"; new Blob([d]);</script>`
	email := &pipeline.Email{HTMLBody: html}
	res := s.Scan(context.Background(), email)
	if res.Verdict != "clean" {
		t.Fatalf("payload below threshold should be clean, got %s", res.Verdict)
	}
}

func TestHTMLSmuggling_CustomThreshold(t *testing.T) {
	// Lower threshold to 5KB; 6KB payload should trigger
	s := newHTMLSmugglingScanner(t, true, 5)
	b64 := largeB64(6)
	html := `<script>var d="` + b64 + `"; new Blob([d]);</script>`
	email := &pipeline.Email{HTMLBody: html}
	res := s.Scan(context.Background(), email)
	if res.Verdict != "suspicious" {
		t.Fatalf("6KB payload with 5KB threshold should be suspicious, got %s", res.Verdict)
	}
}

func TestHTMLSmuggling_MultipleAPIsDetected(t *testing.T) {
	s := newHTMLSmugglingScanner(t, true, 10)
	b64 := largeB64(11)
	html := `<script>var d="` + b64 + `"; var blob = new Blob([d]); var u = URL.createObjectURL(blob);</script>`
	email := &pipeline.Email{HTMLBody: html}
	res := s.Scan(context.Background(), email)
	if res.Verdict != "suspicious" {
		t.Fatalf("expected suspicious, got %s", res.Verdict)
	}

	var hits []db.HTMLSmugglingHit
	if err := json.Unmarshal(res.Matches, &hits); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(hits[0].BlobAPIs) < 2 {
		t.Errorf("expected multiple APIs detected, got %v", hits[0].BlobAPIs)
	}
}

func TestHTMLSmuggling_SetEnabled(t *testing.T) {
	s := newHTMLSmugglingScanner(t, true, 10)
	if !s.IsEnabled() {
		t.Fatal("expected enabled")
	}
	s.SetEnabled(false)
	if s.IsEnabled() {
		t.Fatal("expected disabled after SetEnabled(false)")
	}
	b64 := largeB64(11)
	html := `<script>var d="` + b64 + `"; new Blob([d]);</script>`
	email := &pipeline.Email{HTMLBody: html}
	res := s.Scan(context.Background(), email)
	if res.Verdict != "skip" {
		t.Fatalf("expected skip after disable, got %s", res.Verdict)
	}
}

func TestHTMLSmuggling_MatchesJSON_Struct(t *testing.T) {
	// Verify that Matches deserialises cleanly into []db.HTMLSmugglingHit
	s := newHTMLSmugglingScanner(t, true, 10)
	b64 := largeB64(11)
	html := `<script>var d="` + b64 + `"; var blob = new Blob([d]);</script>`
	email := &pipeline.Email{HTMLBody: html}
	res := s.Scan(context.Background(), email)

	var hits []db.HTMLSmugglingHit
	if err := json.Unmarshal(res.Matches, &hits); err != nil {
		t.Fatalf("Matches is not valid []db.HTMLSmugglingHit JSON: %v", err)
	}
	if len(hits) == 0 {
		t.Fatal("expected at least one hit in Matches")
	}
	hit := hits[0]
	if hit.Source == "" {
		t.Error("hit.Source must not be empty")
	}
	if len(hit.BlobAPIs) == 0 {
		t.Error("hit.BlobAPIs must not be empty")
	}
	if hit.B64SizeKB <= 0 {
		t.Error("hit.B64SizeKB must be positive")
	}
}
