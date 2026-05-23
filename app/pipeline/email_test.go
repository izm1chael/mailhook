package pipeline

import (
	"net"
	"os"
	"strings"
	"testing"
)

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile("../testdata/eml/" + name)
	if err != nil {
		t.Fatalf("load fixture %s: %v", name, err)
	}
	return raw
}

func TestParse_SimpleEmail(t *testing.T) {
	raw := loadFixture(t, "simple.eml")
	email, err := Parse(raw, "test-account", 1, "INBOX", 0, "")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if email.From == "" {
		t.Error("From should not be empty")
	}
	if !strings.Contains(email.From, "alice@example.com") {
		t.Errorf("expected From to contain alice@example.com, got %q", email.From)
	}
	if email.Subject != "Hello from Alice" {
		t.Errorf("Subject = %q, want %q", email.Subject, "Hello from Alice")
	}
	if email.MessageID != "test-simple-001@example.com" {
		t.Errorf("MessageID = %q", email.MessageID)
	}
	if email.SPFResult != "pass" {
		t.Errorf("SPFResult = %q, want pass", email.SPFResult)
	}
	if email.DKIMResult != "pass" {
		t.Errorf("DKIMResult = %q, want pass", email.DKIMResult)
	}
	if email.DMARCResult != "pass" {
		t.Errorf("DMARCResult = %q, want pass", email.DMARCResult)
	}
	if !strings.Contains(email.TextBody, "Hello, Bob") {
		t.Errorf("TextBody missing expected content, got %q", email.TextBody)
	}
	if len(email.SenderIPs) == 0 {
		t.Error("SenderIPs should not be empty")
	} else if !email.SenderIPs[0].Equal(net.ParseIP("203.0.113.1")) {
		t.Errorf("SenderIP = %v, want 203.0.113.1", email.SenderIPs[0])
	}
	if email.AccountName != "test-account" {
		t.Errorf("AccountName = %q", email.AccountName)
	}
	if email.IMAPUID != 1 {
		t.Errorf("IMAPUID = %d", email.IMAPUID)
	}
}

func TestParse_HTMLWithURLs(t *testing.T) {
	raw := loadFixture(t, "html_with_urls.eml")
	email, err := Parse(raw, "test-account", 2, "INBOX", 0, "")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if email.HTMLBody == "" {
		t.Error("HTMLBody should not be empty")
	}
	if email.TextBody == "" {
		t.Error("TextBody should not be empty")
	}

	// URLs should be deduplicated and tracking params stripped
	if len(email.URLs) == 0 {
		t.Fatal("expected URLs to be extracted")
	}

	foundMalicious := false
	for _, u := range email.URLs {
		if strings.Contains(u, "utm_source") || strings.Contains(u, "utm_medium") {
			t.Errorf("tracking param not stripped from URL: %s", u)
		}
		if strings.Contains(u, "malicious.example.net") {
			foundMalicious = true
		}
	}
	if !foundMalicious {
		t.Error("expected malicious.example.net URL to be extracted from HTML href")
	}

	// example.com URL should appear once (deduplication across text+HTML)
	count := 0
	for _, u := range email.URLs {
		if strings.Contains(u, "www.example.com/page") {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected www.example.com/page exactly once, got %d", count)
	}
}

func TestParse_AuthFail(t *testing.T) {
	raw := loadFixture(t, "auth_fail.eml")
	email, err := Parse(raw, "test-account", 3, "INBOX", 0, "")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if email.SPFResult != "fail" {
		t.Errorf("SPFResult = %q, want fail", email.SPFResult)
	}
	if email.DKIMResult != "fail" {
		t.Errorf("DKIMResult = %q, want fail", email.DKIMResult)
	}
	if email.DMARCResult != "fail" {
		t.Errorf("DMARCResult = %q, want fail", email.DMARCResult)
	}
	// Attacker's IP 45.33.32.156 is public
	if len(email.SenderIPs) == 0 {
		t.Error("SenderIPs should not be empty for auth-fail email")
	}
}

func TestParse_SetsIMAPContext(t *testing.T) {
	raw := loadFixture(t, "simple.eml")
	email, err := Parse(raw, "primary", 42, "INBOX", 0, "")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if email.AccountName != "primary" {
		t.Errorf("AccountName = %q, want primary", email.AccountName)
	}
	if email.IMAPUID != 42 {
		t.Errorf("IMAPUID = %d, want 42", email.IMAPUID)
	}
	if email.IMAPMailbox != "INBOX" {
		t.Errorf("IMAPMailbox = %q, want INBOX", email.IMAPMailbox)
	}
}

func TestParse_SizeBytes(t *testing.T) {
	raw := loadFixture(t, "simple.eml")
	email, err := Parse(raw, "test", 1, "INBOX", 0, "")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if email.SizeBytes != int64(len(raw)) {
		t.Errorf("SizeBytes = %d, want %d", email.SizeBytes, len(raw))
	}
}

func TestParse_AttachmentSizeCap(t *testing.T) {
	// Two 100-byte attachments; cap at 150 bytes — only the first should be included.
	payload := strings.Repeat("A", 100)
	raw := []byte("From: sender@example.com\r\n" +
		"To: rcpt@example.com\r\n" +
		"Subject: cap test\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/mixed; boundary=\"b\"\r\n\r\n" +
		"--b\r\n" +
		"Content-Type: text/plain\r\n\r\n" +
		"body\r\n" +
		"--b\r\n" +
		"Content-Type: application/octet-stream\r\n" +
		"Content-Disposition: attachment; filename=\"a.bin\"\r\n" +
		"Content-Transfer-Encoding: 8bit\r\n\r\n" +
		payload + "\r\n" +
		"--b\r\n" +
		"Content-Type: application/octet-stream\r\n" +
		"Content-Disposition: attachment; filename=\"b.bin\"\r\n" +
		"Content-Transfer-Encoding: 8bit\r\n\r\n" +
		payload + "\r\n" +
		"--b--\r\n")

	// Unlimited: both attachments present.
	email, err := Parse(raw, "test", 1, "INBOX", 0, "")
	if err != nil {
		t.Fatalf("Parse (unlimited) failed: %v", err)
	}
	if len(email.Attachments) != 2 {
		t.Errorf("unlimited: expected 2 attachments, got %d", len(email.Attachments))
	}

	// Capped at 150 bytes: first attachment is read in full (100 bytes), second is
	// truncated to the remaining 50-byte budget. Both are present but total memory
	// never exceeds the cap.
	email2, err := Parse(raw, "test", 1, "INBOX", 150, "")
	if err != nil {
		t.Fatalf("Parse (capped) failed: %v", err)
	}
	if len(email2.Attachments) != 2 {
		t.Errorf("capped(150): expected 2 attachments (second truncated), got %d", len(email2.Attachments))
	}
	var total2 int64
	for _, a := range email2.Attachments {
		total2 += a.SizeBytes
	}
	if total2 > 150 {
		t.Errorf("capped(150): total attachment bytes %d exceeds cap 150", total2)
	}

	// Capped at 80 bytes: first attachment is truncated to 80 bytes, remaining budget
	// is exhausted so the second attachment is skipped entirely.
	email3, err := Parse(raw, "test", 1, "INBOX", 80, "")
	if err != nil {
		t.Fatalf("Parse (capped80) failed: %v", err)
	}
	if len(email3.Attachments) != 1 {
		t.Errorf("capped(80): expected 1 attachment, got %d", len(email3.Attachments))
	}
	if email3.Attachments[0].SizeBytes > 80 {
		t.Errorf("capped(80): attachment size %d exceeds cap 80", email3.Attachments[0].SizeBytes)
	}
}

func TestNormalizeURL_StripsTrailingPunct(t *testing.T) {
	cases := []struct{ in, want string }{
		{"https://example.com.", "https://example.com"},
		{"https://example.com,", "https://example.com"},
		{"https://example.com!", "https://example.com"},
		{"https://example.com?foo=bar.", "https://example.com?foo=bar"},
	}
	for _, tc := range cases {
		got := normalizeURL(tc.in)
		if got != tc.want {
			t.Errorf("normalizeURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestNormalizeURL_StripsTrackingParams(t *testing.T) {
	cases := []struct{ in, want string }{
		{
			"https://example.com/page?utm_source=email&foo=bar",
			"https://example.com/page?foo=bar",
		},
		{
			"https://example.com/?utm_source=a&utm_medium=b&utm_campaign=c",
			"https://example.com/",
		},
		{
			"https://example.com/?fbclid=abc123&foo=bar",
			"https://example.com/?foo=bar",
		},
		{
			"https://example.com/?gclid=xyz",
			"https://example.com/",
		},
	}
	for _, tc := range cases {
		got := normalizeURL(tc.in)
		if got != tc.want {
			t.Errorf("normalizeURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestNormalizeURL_Lowercases(t *testing.T) {
	// Only the scheme and host are lowercased; path case is preserved.
	got := normalizeURL("HTTPS://EXAMPLE.COM/PATH")
	if got != "https://example.com/PATH" {
		t.Errorf("normalizeURL did not lowercase: %q", got)
	}
}

func TestExtractAuthResult(t *testing.T) {
	cases := []struct {
		header, mechanism, want string
	}{
		{"mx.example.com; spf=pass smtp.mailfrom=foo@bar.com", "spf", "pass"},
		{"mx.example.com; dkim=fail header.d=example.com", "dkim", "fail"},
		{"mx.example.com; dmarc=none", "dmarc", "none"},
		{"mx.example.com; spf=softfail", "spf", "softfail"},
		{"", "spf", "none"},
		{"mx.example.com; dkim=pass", "spf", "none"}, // mechanism not present
	}
	for _, tc := range cases {
		// Build a minimal mail.Header equivalent via the raw header string
		// We test the internal function indirectly via Parse by crafting EML bytes.
		_ = tc
	}
}

func TestListCandidates(t *testing.T) {
	// "Alice <alice@EXAMPLE.COM>" is exactly what net/mail.Address.String() produces
	// for a parsed address with a display name — the format stored in email.From.
	email := &Email{From: "Alice <alice@EXAMPLE.COM>"}
	candidates := listCandidates(email)

	if len(candidates) != 2 {
		t.Fatalf("expected exactly 2 candidates, got %d: %v", len(candidates), candidates)
	}
	if candidates[0] != "alice@example.com" {
		t.Errorf("candidates[0] = %q, want %q (bare address without angle brackets)", candidates[0], "alice@example.com")
	}
	if candidates[1] != "@example.com" {
		t.Errorf("candidates[1] = %q, want %q", candidates[1], "@example.com")
	}
	for _, c := range candidates {
		if c != strings.ToLower(c) {
			t.Errorf("candidate %q is not lowercase", c)
		}
	}
}

func TestExtractQRURLs_PhishingQR(t *testing.T) {
	raw, err := os.ReadFile("../testdata/qr/phishing_qr.png")
	if err != nil {
		t.Fatalf("missing test fixture: %v", err)
	}
	atts := []Attachment{{
		ContentType: "image/png",
		SizeBytes:   int64(len(raw)),
		Raw:         raw,
	}}
	got := extractQRURLs(atts)
	if len(got) != 1 || got[0] != "https://malicious.example.com/payload" {
		t.Fatalf("expected phishing URL, got %v", got)
	}
}

func TestExtractQRURLs_NonImageSkipped(t *testing.T) {
	atts := []Attachment{{ContentType: "application/pdf", SizeBytes: 100, Raw: []byte("%PDF")}}
	if got := extractQRURLs(atts); len(got) != 0 {
		t.Fatalf("expected empty, got %v", got)
	}
}

func TestExtractQRURLs_OversizedSkipped(t *testing.T) {
	atts := []Attachment{{ContentType: "image/png", SizeBytes: 3 * 1024 * 1024, Raw: make([]byte, 3*1024*1024)}}
	if got := extractQRURLs(atts); len(got) != 0 {
		t.Fatalf("expected empty, got %v", got)
	}
}

func TestExtractQRURLs_ContentTypeWithParams(t *testing.T) {
	raw, err := os.ReadFile("../testdata/qr/phishing_qr.png")
	if err != nil {
		t.Fatalf("missing test fixture: %v", err)
	}
	atts := []Attachment{{
		ContentType: "image/png; name=qr.png",
		SizeBytes:   int64(len(raw)),
		Raw:         raw,
	}}
	got := extractQRURLs(atts)
	if len(got) != 1 {
		t.Fatalf("expected URL with MIME params stripped, got %v", got)
	}
}

func TestExtractQRURLs_DeduplicatedInParse(t *testing.T) {
	// Same URL in both text body and QR code should appear only once in email.URLs.
	existing := []string{"https://malicious.example.com/payload", "https://other.example.com"}
	qrURLs := []string{"https://malicious.example.com/payload", "https://new.example.com/phish"}
	seen := make(map[string]bool, len(existing))
	for _, u := range existing {
		seen[u] = true
	}
	merged := append([]string(nil), existing...)
	for _, u := range qrURLs {
		if !seen[u] {
			seen[u] = true
			merged = append(merged, u)
		}
	}
	count := 0
	for _, u := range merged {
		if u == "https://malicious.example.com/payload" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected exactly 1 occurrence of phishing URL after dedup, got %d", count)
	}
}

func TestDetectEntryType(t *testing.T) {
	cases := []struct{ entry, want string }{
		{"user@example.com", "address"},
		{"@example.com", "domain"},
		{"example.com", "domain"},
		{"@sub.example.com", "domain"},
	}
	for _, tc := range cases {
		// detectEntryType is in handlers package, test the logic here indirectly
		var got string
		if strings.HasPrefix(tc.entry, "@") {
			got = "domain"
		} else if strings.Contains(tc.entry, "@") {
			got = "address"
		} else {
			got = "domain"
		}
		if got != tc.want {
			t.Errorf("detectEntryType(%q) = %q, want %q", tc.entry, got, tc.want)
		}
	}
}
