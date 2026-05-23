package pipeline_test

// pipeline_integration_test.go wires up the full scanner stack with:
//
//   - A mock Rspamd HTTP server returning a high-spam score
//   - A mock clamd TCP server that detects the EICAR test signature
//   - A stub feed manager seeded with a known-malicious domain
//   - A stub IMAP actions handler (no real IMAP needed)
//
// Together these verify that a crafted email flows from Process() through all
// scanners and lands in the DB with the expected verdict.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net"
	"os"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/izm1chael/mailhook/config"
	"github.com/izm1chael/mailhook/db"
	"github.com/izm1chael/mailhook/feeds"
	"github.com/izm1chael/mailhook/notify"
	"github.com/izm1chael/mailhook/pipeline"
	"github.com/izm1chael/mailhook/scanners"
	"github.com/izm1chael/mailhook/storage"
	"github.com/izm1chael/mailhook/web"
)

// ── stubs ─────────────────────────────────────────────────────────────────────

type stubActions struct{}

func (s *stubActions) MoveToQuarantine(_ context.Context, _ string, _ uint32) (uint32, string, error) {
	return 0, "", nil
}
func (s *stubActions) ReleaseToInbox(_ context.Context, _ uint32) error             { return nil }
func (s *stubActions) DeleteMessage(_ context.Context, _ string, _ uint32) error    { return nil }
func (s *stubActions) FlagMessage(_ context.Context, _ string, _ uint32) error      { return nil }

type stubSSE struct{}

func (s *stubSSE) Broadcast(_ []byte) {}

// seedFeed implements the feedManager interface expected by scanners.NewURLCheck.
// feedName is returned by LookupURL — defaults to "urlhaus" if empty.
type seedFeed struct {
	domains  []string
	feedName string // optional: override returned feed name (e.g. "threatfox")
}

func (f *seedFeed) ContainsURL(rawURL string) bool {
	for _, d := range f.domains {
		if strings.Contains(rawURL, d) {
			return true
		}
	}
	return false
}

func (f *seedFeed) LookupURL(rawURL string) (feed, threatType string, ok bool) {
	name := f.feedName
	if name == "" {
		name = "urlhaus"
	}
	for _, d := range f.domains {
		if strings.Contains(rawURL, d) {
			return name, "malware", true
		}
	}
	return "", "", false
}

func (f *seedFeed) LookupURLExact(rawURL string) (feed, threatType string, ok bool) {
	return f.LookupURL(rawURL)
}

// ── mock Rspamd HTTP server ───────────────────────────────────────────────────

// startMockRspamd starts an httptest server that returns a spam verdict.
func startMockRspamd(t *testing.T, action string, score float64) *httptest.Server {
	t.Helper()
	resp := map[string]interface{}{
		"action": action,
		"score":  score,
		"symbols": map[string]interface{}{
			"BAYES_SPAM": map[string]interface{}{"score": score, "description": "Bayesian spam"},
		},
	}
	b, _ := json.Marshal(resp)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(b) // nosemgrep: go.lang.security.audit.xss.no-direct-write-to-responsewriter.no-direct-write-to-responsewriter
	}))
}

// ── mock clamd TCP server ─────────────────────────────────────────────────────

// startMockClamd listens on a random TCP port.
// If the email body contains the EICAR test string the server returns FOUND.
func startMockClamd(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("clamd mock listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() }) //nolint:errcheck

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveClamdConn(conn)
		}
	}()
	return ln.Addr().String()
}

// serveClamdConn speaks just enough of the clamd protocol for MailHook's client:
//
//	zPING\0          → PONG\0
//	zINSTREAM\0 + chunks + zero-terminator → stream: <result>\0
func serveClamdConn(conn net.Conn) {
	defer conn.Close() //nolint:errcheck

	buf := bufio.NewReader(conn)
	// Read the null-terminated command.
	cmd, err := buf.ReadString('\x00')
	if err != nil {
		return
	}
	cmd = strings.TrimRight(cmd, "\x00")

	switch cmd {
	case "zPING":
		fmt.Fprint(conn, "PONG\x00") //nolint:errcheck
	case "zINSTREAM":
		// Read chunked stream: [4-byte big-endian len][data] ... [0x00000000]
		var body []byte
		for {
			var chunkLen uint32
			if err := binary.Read(buf, binary.BigEndian, &chunkLen); err != nil {
				return
			}
			if chunkLen == 0 {
				break
			}
			chunk := make([]byte, chunkLen)
			if _, err := io.ReadFull(buf, chunk); err != nil {
				return
			}
			body = append(body, chunk...)
		}
		// Detect EICAR by its distinctive first two bytes X5O!
		if strings.Contains(string(body), "X5O!P%@AP") {
			fmt.Fprint(conn, "stream: EICAR-Test-Signature FOUND\x00") //nolint:errcheck
		} else {
			fmt.Fprint(conn, "stream: OK\x00") //nolint:errcheck
		}
	}
}

// ── test email corpus ─────────────────────────────────────────────────────────

// EICAR is the standard antivirus test string — safe to embed in source code,
// universally recognised by AV engines as a test artifact.
// Ref: https://www.eicar.org/download-anti-malware-testfile/
const eicarTestString = `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`

// buildEmail returns a raw RFC822 message containing:
//   - EICAR test string in the body (triggers ClamAV)
//   - a URL pointing at a seeded malicious domain (triggers URL feed)
//   - a Received header with a sending IP (exercised by IPReputation if API key set)
func buildEmail(maliciousDomain string) []byte {
	body := fmt.Sprintf(
		"Click here: http://%s/malware.exe\r\n"+
			"Virus payload: %s\r\n",
		maliciousDomain, eicarTestString,
	)
	raw := "From: evil@phish.example\r\n" +
		"To: victim@corp.example\r\n" +
		"Subject: You have won!\r\n" +
		"Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n" +
		"Message-ID: <eicar-url-test@example.com>\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"Received: from mail.phish.example (198.51.100.42) by mx.corp.example\r\n" +
		"\r\n" +
		body
	return []byte(raw)
}

// ── test ──────────────────────────────────────────────────────────────────────

func TestPipelineFullScanEICAR(t *testing.T) {
	dir := t.TempDir()

	gdb, err := db.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	if err := gdb.Migrate(); err != nil {
		t.Fatalf("db.Migrate: %v", err)
	}

	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	store, err := storage.New(dir, log)
	if err != nil {
		t.Fatalf("storage.New: %v", err)
	}

	// Rspamd: return high spam score so verdict tips to SPAM.
	rspamdSrv := startMockRspamd(t, "add header", 8.5)
	t.Cleanup(rspamdSrv.Close)
	rspamd := scanners.NewRspamd(rspamdSrv.URL, log)

	// ClamAV: mock clamd returns EICAR-Test-Signature FOUND for EICAR content.
	clamdAddr := startMockClamd(t)
	clamav := scanners.NewClamAV(clamdAddr, log)

	// YARA: disabled — no rules dir available in CI.
	yaraScanner, err := scanners.NewYARA("", log)
	if err != nil {
		t.Fatalf("NewYARA: %v", err)
	}

	// URL feed: seed with our malicious domain.
	maliciousDomain := "badsite.example"
	feed := &seedFeed{domains: []string{maliciousDomain}}
	urlCheck := scanners.NewURLCheck(feed, log)

	// IP reputation and VirusTotal: no API keys → they return "unavailable" (skip verdict).
	ipRep := scanners.NewIPReputation("", gdb, log)
	vt := scanners.NewVirusTotal("", gdb, log, 24*time.Hour, 4*time.Hour)

	cfg := &config.Config{
		SpamScore:   5.0,
		RejectScore: 15.0,
		DataDir:     dir,
	}

	hub := web.NewSSEHub()
	notifier := notify.New(cfg, log)
	actions := &stubActions{}
	if err := web.InitTemplates(); err != nil {
		t.Fatalf("web.InitTemplates: %v", err)
	}

	allScanners := []pipeline.Scanner{rspamd, clamav, yaraScanner, urlCheck, ipRep, vt}
	p := pipeline.New(allScanners, store, gdb, actions, hub, notifier, cfg, log, nil)

	raw := buildEmail(maliciousDomain)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	p.Process(ctx, "test-account", raw, 1, "INBOX")

	// Give any async DB writes a moment to settle.
	time.Sleep(100 * time.Millisecond)

	// Verify a Scan record was created.
	var scans []db.Scan
	if err := gdb.Find(&scans).Error; err != nil {
		t.Fatalf("query scans: %v", err)
	}
	if len(scans) == 0 {
		t.Fatal("no Scan record created after pipeline.Process")
	}

	s := scans[0]

	// ClamAV must have flagged the EICAR string.
	if !strings.Contains(s.ClamAVStatus, "EICAR") {
		t.Errorf("ClamAVStatus = %q, want to contain EICAR", s.ClamAVStatus)
	}

	// Rspamd score must reflect the mock response (8.5).
	if s.RspamdScore < 8.0 {
		t.Errorf("RspamdScore = %.1f, want >= 8.0", s.RspamdScore)
	}

	// Verdict must be MALWARE (ClamAV hit takes priority over SPAM and URL).
	if s.Verdict != db.VerdictMalware {
		t.Errorf("Verdict = %q, want MALWARE", s.Verdict)
	}

	// VerdictReason should name the ClamAV signature.
	if !strings.Contains(s.VerdictReason, "EICAR") {
		t.Errorf("VerdictReason = %q, want to contain EICAR", s.VerdictReason)
	}

	t.Logf("verdict=%s clamav=%s rspamd_score=%.1f reason=%s",
		s.Verdict, s.ClamAVStatus, s.RspamdScore, s.VerdictReason)
}

func TestPipelineCleanEmail(t *testing.T) {
	dir := t.TempDir()

	gdb, err := db.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	if err := gdb.Migrate(); err != nil {
		t.Fatalf("db.Migrate: %v", err)
	}

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	store, err := storage.New(dir, log)
	if err != nil {
		t.Fatalf("storage.New: %v", err)
	}

	// Rspamd returns clean score.
	rspamdSrv := startMockRspamd(t, "no action", 0.5)
	t.Cleanup(rspamdSrv.Close)

	clamdAddr := startMockClamd(t)

	cfg := &config.Config{SpamScore: 5.0, RejectScore: 15.0, DataDir: dir}
	hub := web.NewSSEHub()
	notifier := notify.New(cfg, log)
	if err := web.InitTemplates(); err != nil {
		t.Fatalf("web.InitTemplates: %v", err)
	}

	allScanners := []pipeline.Scanner{
		scanners.NewRspamd(rspamdSrv.URL, log),
		scanners.NewClamAV(clamdAddr, log),
		scanners.NewURLCheck(&seedFeed{}, log),
		scanners.NewIPReputation("", gdb, log),
		scanners.NewVirusTotal("", gdb, log, 24*time.Hour, 4*time.Hour),
	}

	p := pipeline.New(allScanners, store, gdb, &stubActions{}, hub, notifier, cfg, log, nil)

	clean := []byte("From: alice@example.com\r\n" +
		"To: bob@example.com\r\n" +
		"Subject: Hello\r\n" +
		"Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n" +
		"Message-ID: <clean-test-001@example.com>\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"Authentication-Results: mx.example.com;\r\n" +
		"  spf=pass smtp.mailfrom=alice@example.com;\r\n" +
		"  dkim=pass header.d=example.com;\r\n" +
		"  dmarc=pass header.from=example.com\r\n" +
		"Received: from mail.example.com ([203.0.113.1]) by mx.example.com\r\n" +
		"\r\n" +
		"Hi Bob!\r\n")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	p.Process(ctx, "test-account", clean, 2, "INBOX")
	time.Sleep(100 * time.Millisecond)

	var scans []db.Scan
	if err := gdb.Find(&scans).Error; err != nil {
		t.Fatalf("query scans: %v", err)
	}
	if len(scans) == 0 {
		t.Fatal("no Scan record created")
	}
	if scans[0].Verdict != db.VerdictClean {
		t.Errorf("clean email verdict = %q, want CLEAN", scans[0].Verdict)
	}
	t.Logf("verdict=%s rspamd_score=%.1f", scans[0].Verdict, scans[0].RspamdScore)
}

// TestPipelineRescanUpsert verifies that processing the same account+UID twice
// (e.g. on rescan) updates the existing scan record rather than creating a duplicate,
// and that the IMAP action runs on both passes.
func TestPipelineRescanUpsert(t *testing.T) {
	dir := t.TempDir()

	gdb, err := db.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	if err := gdb.Migrate(); err != nil {
		t.Fatalf("db.Migrate: %v", err)
	}

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	store, err := storage.New(dir, log)
	if err != nil {
		t.Fatalf("storage.New: %v", err)
	}

	rspamdSrv := startMockRspamd(t, "no action", 0.5)
	t.Cleanup(rspamdSrv.Close)
	clamdAddr := startMockClamd(t)

	cfg := &config.Config{SpamScore: 5.0, RejectScore: 15.0, DataDir: dir}
	hub := web.NewSSEHub()
	notifier := notify.New(cfg, log)
	if err := web.InitTemplates(); err != nil {
		t.Fatalf("web.InitTemplates: %v", err)
	}

	actionsCalled := &countingActions{}
	allScanners := []pipeline.Scanner{
		scanners.NewRspamd(rspamdSrv.URL, log),
		scanners.NewClamAV(clamdAddr, log),
		scanners.NewURLCheck(&seedFeed{}, log),
		scanners.NewIPReputation("", gdb, log),
		scanners.NewVirusTotal("", gdb, log, 24*time.Hour, 4*time.Hour),
	}

	p := pipeline.New(allScanners, store, gdb, actionsCalled, hub, notifier, cfg, log, nil)

	raw := []byte("From: alice@example.com\r\n" +
		"To: bob@example.com\r\n" +
		"Subject: Dup test\r\n" +
		"Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n" +
		"Message-ID: <dup-test@example.com>\r\n" +
		"\r\n" +
		"Duplicate test.\r\n")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// First call succeeds and creates a DB record.
	p.Process(ctx, "test-account", raw, 99, "INBOX")
	time.Sleep(50 * time.Millisecond)

	var scans []db.Scan
	if err := gdb.Find(&scans).Error; err != nil {
		t.Fatalf("query scans: %v", err)
	}
	if len(scans) != 1 {
		t.Fatalf("expected 1 scan record after first Process, got %d", len(scans))
	}
	firstActionCount := actionsCalled.count

	// Second call with the same account+UID simulates a rescan — upsert must update
	// the existing record (not create a duplicate) and the IMAP action should run again.
	p.Process(ctx, "test-account", raw, 99, "INBOX")
	time.Sleep(50 * time.Millisecond)

	// Still exactly one scan record (upsert, not insert).
	var scans2 []db.Scan
	if err := gdb.Find(&scans2).Error; err != nil {
		t.Fatalf("query scans after rescan: %v", err)
	}
	if len(scans2) != 1 {
		t.Errorf("expected 1 scan record after rescan (upsert), got %d", len(scans2))
	}

	// IMAP action ran for both passes (rescan re-applies the pipeline action).
	if actionsCalled.count != firstActionCount+1 {
		t.Errorf("IMAP action count = %d after rescan, want %d", actionsCalled.count, firstActionCount+1)
	}
}

// countingActions counts IMAP action calls.
type countingActions struct{ count int }

func (c *countingActions) MoveToQuarantine(_ context.Context, _ string, _ uint32) (uint32, string, error) {
	c.count++
	return 0, "", nil
}
func (c *countingActions) ReleaseToInbox(_ context.Context, _ uint32) error {
	c.count++
	return nil
}
func (c *countingActions) DeleteMessage(_ context.Context, _ string, _ uint32) error {
	c.count++
	return nil
}
func (c *countingActions) FlagMessage(_ context.Context, _ string, _ uint32) error {
	c.count++
	return nil
}

// TestPipelineScannerResultsPersisted verifies that the structured scanner result
// columns (RspamdSymbols, URLHits, etc.) are populated in the Scan record.
func TestPipelineScannerResultsPersisted(t *testing.T) {
	dir := t.TempDir()

	gdb, err := db.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	if err := gdb.Migrate(); err != nil {
		t.Fatalf("db.Migrate: %v", err)
	}

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	store, err := storage.New(dir, log)
	if err != nil {
		t.Fatalf("storage.New: %v", err)
	}

	// Rspamd returns a high spam score with symbols.
	rspamdSrv := startMockRspamdWithSymbols(t)
	t.Cleanup(rspamdSrv.Close)
	clamdAddr := startMockClamd(t)

	maliciousDomain := "urlhit.example"
	feed := &seedFeed{domains: []string{maliciousDomain}}

	cfg := &config.Config{SpamScore: 5.0, RejectScore: 15.0, DataDir: dir}
	hub := web.NewSSEHub()
	notifier := notify.New(cfg, log)
	if err := web.InitTemplates(); err != nil {
		t.Fatalf("web.InitTemplates: %v", err)
	}

	allScanners := []pipeline.Scanner{
		scanners.NewRspamd(rspamdSrv.URL, log),
		scanners.NewClamAV(clamdAddr, log),
		scanners.NewURLCheck(feed, log),
		scanners.NewIPReputation("", gdb, log),
		scanners.NewVirusTotal("", gdb, log, 24*time.Hour, 4*time.Hour),
	}

	p := pipeline.New(allScanners, store, gdb, &stubActions{}, hub, notifier, cfg, log, nil)

	raw := []byte(fmt.Sprintf(
		"From: spam@badactor.example\r\n"+
			"To: victim@corp.example\r\n"+
			"Subject: Buy now!\r\n"+
			"Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n"+
			"Message-ID: <symbols-test-001@example.com>\r\n"+
			"\r\n"+
			"Click here: http://%s/buy\r\n", maliciousDomain))

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	p.Process(ctx, "persist-account", raw, 7, "INBOX")
	time.Sleep(100 * time.Millisecond)

	var scans []db.Scan
	if err := gdb.Find(&scans).Error; err != nil {
		t.Fatalf("query scans: %v", err)
	}
	if len(scans) == 0 {
		t.Fatal("no Scan record created")
	}
	s := scans[0]

	// RspamdSymbols should be populated (mock returns symbols).
	if len(s.RspamdSymbols) == 0 || string(s.RspamdSymbols) == "null" {
		t.Errorf("RspamdSymbols not populated: %s", s.RspamdSymbols)
	}

	// URLHits should be populated since the email contains a URL from the feed.
	if len(s.URLHits) == 0 || string(s.URLHits) == "null" {
		t.Errorf("URLHits not populated: %s", s.URLHits)
	}

	t.Logf("RspamdSymbols=%s URLHits=%s", s.RspamdSymbols, s.URLHits)
}

// TestPipelineThreatFoxURLHit verifies that a URL matched by the ThreatFox feed
// produces a PHISH verdict and stores the feed name "threatfox" in URLHits.
func TestPipelineThreatFoxURLHit(t *testing.T) {
	dir := t.TempDir()

	gdb, err := db.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	if err := gdb.Migrate(); err != nil {
		t.Fatalf("db.Migrate: %v", err)
	}

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	store, err := storage.New(dir, log)
	if err != nil {
		t.Fatalf("storage.New: %v", err)
	}

	rspamdSrv := startMockRspamd(t, "no action", 1.0)
	t.Cleanup(rspamdSrv.Close)
	clamdAddr := startMockClamd(t)

	// Seed with a ThreatFox-attributed URL/domain.
	tfDomain := "botnet-c2.example"
	feed := &seedFeed{domains: []string{tfDomain}, feedName: "threatfox"}
	urlCheck := scanners.NewURLCheck(feed, log)

	cfg := &config.Config{SpamScore: 5.0, RejectScore: 15.0, DataDir: dir}
	hub := web.NewSSEHub()
	notifier := notify.New(cfg, log)
	if err := web.InitTemplates(); err != nil {
		t.Fatalf("web.InitTemplates: %v", err)
	}

	allScanners := []pipeline.Scanner{
		scanners.NewRspamd(rspamdSrv.URL, log),
		scanners.NewClamAV(clamdAddr, log),
		urlCheck,
		scanners.NewIPReputation("", gdb, log),
		scanners.NewVirusTotal("", gdb, log, 24*time.Hour, 4*time.Hour),
	}
	p := pipeline.New(allScanners, store, gdb, &stubActions{}, hub, notifier, cfg, log, nil)

	raw := []byte(fmt.Sprintf(
		"From: attacker@evil.example\r\n"+
			"To: target@corp.example\r\n"+
			"Subject: C2 beacon\r\n"+
			"Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n"+
			"Message-ID: <threatfox-test@example.com>\r\n"+
			"\r\n"+
			"Beacon: http://%s/gate.php\r\n", tfDomain))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	p.Process(ctx, "tf-account", raw, 10, "INBOX")
	time.Sleep(100 * time.Millisecond)

	var scans []db.Scan
	if err := gdb.Find(&scans).Error; err != nil {
		t.Fatalf("query scans: %v", err)
	}
	if len(scans) == 0 {
		t.Fatal("no Scan record created")
	}
	s := scans[0]

	if s.Verdict != db.VerdictPhish {
		t.Errorf("want PHISH verdict, got %q (reason: %s)", s.Verdict, s.VerdictReason)
	}
	if s.Status != db.StatusQuarantined {
		t.Errorf("want QUARANTINED status, got %q", s.Status)
	}

	// URLHits must contain feed="threatfox".
	if len(s.URLHits) == 0 || string(s.URLHits) == "null" {
		t.Fatal("URLHits not populated")
	}
	var hits []db.URLHit
	if err := json.Unmarshal(s.URLHits, &hits); err != nil {
		t.Fatalf("unmarshal URLHits: %v", err)
	}
	if hits[0].Feed != "threatfox" {
		t.Errorf("URLHit.Feed = %q, want threatfox", hits[0].Feed)
	}

	t.Logf("verdict=%s status=%s url_hits=%s", s.Verdict, s.Status, s.URLHits)
}

// TestPipelineMalwareBazaarHashHit verifies that an attachment whose SHA256 is in
// the MalwareBazaarHash table triggers a MALWARE verdict and populates MBResults.
func TestPipelineMalwareBazaarHashHit(t *testing.T) {
	dir := t.TempDir()

	gdb, err := db.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	if err := gdb.Migrate(); err != nil {
		t.Fatalf("db.Migrate: %v", err)
	}

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	store, err := storage.New(dir, log)
	if err != nil {
		t.Fatalf("storage.New: %v", err)
	}

	// Known attachment content — compute its SHA256 so we can pre-seed the DB.
	attContent := []byte("fake-malware-payload-for-integration-test")
	h := sha256.Sum256(attContent)
	knownSHA256 := fmt.Sprintf("%x", h)
	signature := "FakeRansomware"

	// Pre-seed MalwareBazaarHash so the scanner finds it locally (no network needed).
	gdb.DB.Create(&db.MalwareBazaarHash{
		SHA256:    knownSHA256,
		Signature: signature,
		FileType:  "exe",
	})

	// Wire up a feeds.Manager backed by the same DB so LookupHash works.
	feedMgr := feeds.New(dir, gdb, log)

	rspamdSrv := startMockRspamd(t, "no action", 1.0)
	t.Cleanup(rspamdSrv.Close)
	clamdAddr := startMockClamd(t)

	cfg := &config.Config{SpamScore: 5.0, RejectScore: 15.0, DataDir: dir}
	hub := web.NewSSEHub()
	notifier := notify.New(cfg, log)
	if err := web.InitTemplates(); err != nil {
		t.Fatalf("web.InitTemplates: %v", err)
	}

	mbScanner := scanners.NewMalwareBazaar(feedMgr, log)
	allScanners := []pipeline.Scanner{
		scanners.NewRspamd(rspamdSrv.URL, log),
		scanners.NewClamAV(clamdAddr, log),
		scanners.NewURLCheck(&seedFeed{}, log),
		scanners.NewIPReputation("", gdb, log),
		scanners.NewVirusTotal("", gdb, log, 24*time.Hour, 4*time.Hour),
		mbScanner,
	}
	p := pipeline.New(allScanners, store, gdb, &stubActions{}, hub, notifier, cfg, log, nil)

	// Build a MIME email containing an .exe attachment with the known content.
	raw := buildMIMEEmailWithAttachment(t, "malware.exe", "application/octet-stream", attContent)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	p.Process(ctx, "mb-account", raw, 20, "INBOX")
	time.Sleep(100 * time.Millisecond)

	var scans []db.Scan
	if err := gdb.Find(&scans).Error; err != nil {
		t.Fatalf("query scans: %v", err)
	}
	if len(scans) == 0 {
		t.Fatal("no Scan record created")
	}
	s := scans[0]

	if s.Verdict != db.VerdictMalware {
		t.Errorf("want MALWARE verdict, got %q (reason: %s)", s.Verdict, s.VerdictReason)
	}
	if s.Status != db.StatusDeleted {
		t.Errorf("want DELETED status, got %q", s.Status)
	}

	// MBResults must be populated and contain the known SHA256 and signature.
	if len(s.MBResults) == 0 || string(s.MBResults) == "null" {
		t.Fatal("MBResults not populated")
	}
	var mbResults []db.MBResult
	if err := json.Unmarshal(s.MBResults, &mbResults); err != nil {
		t.Fatalf("unmarshal MBResults: %v", err)
	}
	if len(mbResults) == 0 {
		t.Fatal("MBResults is empty slice")
	}
	if mbResults[0].SHA256 != knownSHA256 {
		t.Errorf("MBResult.SHA256 = %q, want %q", mbResults[0].SHA256, knownSHA256)
	}
	if mbResults[0].Signature != signature {
		t.Errorf("MBResult.Signature = %q, want %q", mbResults[0].Signature, signature)
	}
	if mbResults[0].Source != "feed" {
		t.Errorf("MBResult.Source = %q, want feed", mbResults[0].Source)
	}

	// MBSignature must also be reflected in the attachment info.
	var attInfos []db.AttachmentInfo
	if err := json.Unmarshal(s.Attachments, &attInfos); err != nil {
		t.Fatalf("unmarshal Attachments: %v", err)
	}
	found := false
	for _, ai := range attInfos {
		if ai.SHA256 == knownSHA256 && ai.MBSignature == signature {
			found = true
		}
	}
	if !found {
		t.Errorf("AttachmentInfo.MBSignature not set for the matched attachment: %s", s.Attachments)
	}

	t.Logf("verdict=%s status=%s mb_results=%s", s.Verdict, s.Status, s.MBResults)
}

// buildMIMEEmailWithAttachment returns a raw RFC822 MIME multipart message
// containing one attachment with the given filename, content type, and body bytes.
func buildMIMEEmailWithAttachment(t *testing.T, filename, contentType string, body []byte) []byte {
	t.Helper()
	var buf bytes.Buffer

	// Write RFC headers.
	fmt.Fprintf(&buf, "From: attacker@evil.example\r\n")
	fmt.Fprintf(&buf, "To: target@corp.example\r\n")
	fmt.Fprintf(&buf, "Subject: Malware delivery\r\n")
	fmt.Fprintf(&buf, "Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n")
	fmt.Fprintf(&buf, "Message-ID: <mb-test-%d@example.com>\r\n", time.Now().UnixNano())
	fmt.Fprintf(&buf, "MIME-Version: 1.0\r\n")

	mw := multipart.NewWriter(&buf)
	fmt.Fprintf(&buf, "Content-Type: multipart/mixed; boundary=%q\r\n\r\n", mw.Boundary())

	// Text part.
	th := make(textproto.MIMEHeader)
	th.Set("Content-Type", "text/plain; charset=utf-8")
	if pw, err := mw.CreatePart(th); err == nil {
		fmt.Fprint(pw, "Please find the attached file.\r\n")
	}

	// Attachment part.
	ah := make(textproto.MIMEHeader)
	ah.Set("Content-Type", contentType)
	ah.Set("Content-Disposition", fmt.Sprintf(`attachment; filename=%q`, filename))
	if pw, err := mw.CreatePart(ah); err == nil {
		pw.Write(body) //nolint:errcheck
	}

	mw.Close() //nolint:errcheck
	return buf.Bytes()
}

// ── EML fixture tests ─────────────────────────────────────────────────────────

// newFixturePipeline returns a pipeline wired with:
//   - mock Rspamd (neutral: score=0.5, no action)
//   - mock ClamAV (always clean)
//   - empty URL feed (no seeded domains)
//   - HTMLSmuggling + HiddenTextDetect scanners (no network)
//   - ONNX stub (returns skip in standard build, real inference in AI build)
//   - no YARA rules (disabled)
func newFixturePipeline(t *testing.T) (p *pipeline.Pipeline, gdb *db.DB) {
	t.Helper()
	dir := t.TempDir()

	var err error
	gdb, err = db.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	if err := gdb.Migrate(); err != nil {
		t.Fatalf("db.Migrate: %v", err)
	}

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	store, err := storage.New(dir, log)
	if err != nil {
		t.Fatalf("storage.New: %v", err)
	}

	rspamdSrv := startMockRspamd(t, "no action", 0.5)
	t.Cleanup(rspamdSrv.Close)
	clamdAddr := startMockClamd(t)

	cfg := &config.Config{
		SpamScore:            5.0,
		RejectScore:          15.0,
		DataDir:              dir,
		HTMLSmugglingEnabled: true,
		HiddenTextEnabled:    true,
	}

	yaraScanner, err := scanners.NewYARA("", log)
	if err != nil {
		t.Fatalf("NewYARA: %v", err)
	}
	onnxScanner, err := scanners.NewONNXScanner(cfg, log)
	if err != nil {
		t.Fatalf("NewONNXScanner: %v", err)
	}

	if err := web.InitTemplates(); err != nil {
		t.Fatalf("web.InitTemplates: %v", err)
	}

	allScanners := []pipeline.Scanner{
		scanners.NewRspamd(rspamdSrv.URL, log),
		scanners.NewClamAV(clamdAddr, log),
		yaraScanner,
		scanners.NewURLCheck(&seedFeed{}, log),
		scanners.NewIPReputation("", gdb, log),
		scanners.NewVirusTotal("", gdb, log, 24*time.Hour, 4*time.Hour),
		scanners.NewHTMLSmuggling(cfg, log),
		scanners.NewHiddenTextDetect(cfg, log),
		onnxScanner,
	}
	p = pipeline.New(allScanners, store, gdb, &stubActions{}, web.NewSSEHub(), notify.New(cfg, log), cfg, log, nil)
	return p, gdb
}

// TestPipelineEMLFixtures processes each EML fixture from testdata/eml/ through
// the full scanner pipeline and asserts the expected standard-build verdict.
//
// AI-build improvements are noted in the aiNote field for documentation:
// they cannot be verified without running 'make models-bert && make models-dga'
// and building with -tags ai.
func TestPipelineEMLFixtures(t *testing.T) {
	cases := []struct {
		eml         string
		wantVerdict string
		// wantStatus is the IMAP/DB status: QUARANTINED for quarantine decisions,
		// INBOX for pass and flag decisions.
		wantStatus string
		// aiNote documents what the AI build would produce, for human review.
		aiNote string
	}{
		{
			eml: "clean_newsletter.eml",
			// SPF/DKIM/DMARC pass, no suspicious content.
			wantVerdict: "CLEAN", wantStatus: db.StatusInbox,
		},
		{
			eml: "simple.eml",
			// Minimal email, auth pass.
			wantVerdict: "CLEAN", wantStatus: db.StatusInbox,
		},
		{
			eml: "html_with_urls.eml",
			// Auth pass, URL not in seeded feed.
			wantVerdict: "CLEAN", wantStatus: db.StatusInbox,
		},
		{
			eml: "dga_domains.eml",
			// Auth pass (SPF/DKIM/DMARC all pass), DGA domains not in URL feed,
			// no NRD result. Standard build cannot detect DGA-pattern domains.
			wantVerdict: "CLEAN", wantStatus: db.StatusInbox,
			aiNote: "AI: DGA CNN scores xvk9m2qp.top high; with auth passing → suspicious (flagged, not quarantined without 2nd signal)",
		},
		{
			eml: "bec_cfo_fraud.eml",
			// SPF softfail + DKIM fail + DMARC fail = allAuthFail (1 suspicious signal).
			// 1 signal → flag; flag maps to INBOX status.
			wantVerdict: "SUSPICIOUS", wantStatus: db.StatusInbox,
			aiNote: "AI: DistilBERT scores wire-transfer BEC prose >0.85 → quarantine/PHISH",
		},
		{
			eml: "phish_novel_url.eml",
			// SPF/DKIM/DMARC all fail; novel phishing URL not in any feed.
			// 1 suspicious signal (allAuthFail) → flag → INBOX.
			wantVerdict: "SUSPICIOUS", wantStatus: db.StatusInbox,
			aiNote: "AI: DistilBERT detects phishing urgency prose >0.85 → quarantine/PHISH",
		},
		{
			eml: "auth_fail.eml",
			// SPF/DKIM/DMARC all fail; BEC-style text, no URLs.
			// 1 suspicious signal → flag → INBOX.
			wantVerdict: "SUSPICIOUS", wantStatus: db.StatusInbox,
			aiNote: "AI: DistilBERT detects BEC prose >0.85 → quarantine/PHISH",
		},
		{
			eml: "html_smuggling.eml",
			// HTML attachment contains base64-encoded JS payload.
			// HTMLSmuggling scanner fires at Priority 5.5 → quarantine regardless of auth.
			wantVerdict: "SUSPICIOUS", wantStatus: db.StatusQuarantined,
		},
		{
			eml: "hidden_text.eml",
			// No auth headers (empty = !pass → allAuthFail=true) + hidden text detected.
			// Two suspicious signals → quarantine.
			wantVerdict: "SUSPICIOUS", wantStatus: db.StatusQuarantined,
		},
	}

	for i, tc := range cases {
		i, tc := i, tc
		t.Run(tc.eml, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("..", "testdata", "eml", tc.eml))
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}

			p, gdb := newFixturePipeline(t)

			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()

			p.Process(ctx, "fixture-account", raw, uint32(200+i), "INBOX")
			time.Sleep(100 * time.Millisecond)

			var scans []db.Scan
			if err := gdb.Find(&scans).Error; err != nil {
				t.Fatalf("query scans: %v", err)
			}
			if len(scans) == 0 {
				t.Fatal("no Scan record created")
			}
			s := scans[0]

			if string(s.Verdict) != tc.wantVerdict {
				t.Errorf("verdict = %q, want %q (reason: %s)", s.Verdict, tc.wantVerdict, s.VerdictReason)
			}
			if s.Status != tc.wantStatus {
				t.Errorf("status = %q, want %q", s.Status, tc.wantStatus)
			}

			if tc.aiNote != "" {
				t.Logf("standard: %s/%s | %s", s.Status, s.Verdict, tc.aiNote)
			} else {
				t.Logf("verdict=%s status=%s reason=%q", s.Verdict, s.Status, s.VerdictReason)
			}
		})
	}
}

// panicScanner is a test-only Scanner that panics when Scan is called.
type panicScanner struct{}

func (panicScanner) Name() string { return "panic" }
func (panicScanner) Scan(_ context.Context, _ *pipeline.Email) pipeline.ScanResult {
	panic("deliberate test panic from panicScanner")
}

// TestPipelineProcessPanicRecovery verifies that a panic inside a scanner goroutine
// does not crash the caller goroutine and that a DB record is still written.
func TestPipelineProcessPanicRecovery(t *testing.T) {
	dir := t.TempDir()
	gdb, err := db.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	if err := gdb.Migrate(); err != nil {
		t.Fatalf("db.Migrate: %v", err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	store, err := storage.New(dir, log)
	if err != nil {
		t.Fatalf("storage.New: %v", err)
	}
	cfg := &config.Config{SpamScore: 5.0, RejectScore: 15.0, DataDir: dir}

	// Include the panicScanner; all other scanners are absent.
	allScanners := []pipeline.Scanner{panicScanner{}}
	p := pipeline.New(allScanners, store, gdb, &stubActions{}, web.NewSSEHub(), notify.New(cfg, log), cfg, log, nil)

	raw := buildEmail("clean.example")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Should NOT panic the test goroutine — the per-scanner recover inside Process must catch it.
	p.Process(ctx, "test-account", raw, 99, "INBOX")
	time.Sleep(50 * time.Millisecond)

	// A scan record should still exist — the pipeline recovered and created one.
	var scans []db.Scan
	if err := gdb.Find(&scans).Error; err != nil {
		t.Fatalf("query scans: %v", err)
	}
	if len(scans) == 0 {
		t.Fatal("expected a Scan record after panic recovery, but none found")
	}
	t.Logf("scan recovered: verdict=%s reason=%q", scans[0].Verdict, scans[0].VerdictReason)
}

// panicParseScanner demonstrates that even if we feed a zero-length raw body,
// Process returns without crashing (error path, not panic path).
func TestPipelineProcessEmptyBody(t *testing.T) {
	dir := t.TempDir()
	gdb, err := db.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	if err := gdb.Migrate(); err != nil {
		t.Fatalf("db.Migrate: %v", err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	store, err := storage.New(dir, log)
	if err != nil {
		t.Fatalf("storage.New: %v", err)
	}
	cfg := &config.Config{SpamScore: 5.0, RejectScore: 15.0, DataDir: dir}
	p := pipeline.New(nil, store, gdb, &stubActions{}, web.NewSSEHub(), notify.New(cfg, log), cfg, log, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// Empty raw bytes should cause Parse() to return an error, not panic.
	p.Process(ctx, "test-account", []byte{}, 100, "INBOX")
	// No assertion — just verifying no crash.
}

// startMockRspamdWithSymbols starts a mock Rspamd that returns symbols in its response.
func startMockRspamdWithSymbols(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/checkv2" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{
				"score": 9.5,
				"action": "add header",
				"symbols": {
					"SPAM_RULE": {"score": 5.0, "description": "Spam rule hit"},
					"BAYES_SPAM": {"score": 4.5, "description": "Bayes spam"}
				}
			}`)
			return
		}
		http.NotFound(w, r)
	}))
}
