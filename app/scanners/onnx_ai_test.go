//go:build ai

package scanners

import (
	"context"
	"log/slog"
	"net"
	"os"
	"testing"
	"time"

	"github.com/izm1chael/mailhook/config"
	"github.com/izm1chael/mailhook/pipeline"
)

func makeONNXTestEmail(body string, urls []string) *pipeline.Email {
	return &pipeline.Email{
		IMAPUID:     1,
		AccountName: "test",
		TextBody:    body,
		URLs:        urls,
		Date:        time.Now(),
		SenderIPs:   []net.IP{},
	}
}

func TestExtractDomains(t *testing.T) {
	urls := []string{
		"https://evil.example.com/path?q=1",
		"http://good.com:8080/",
		"https://evil.example.com/other",
		"ftp://files.test.net/file.zip",
		"not-a-url",
	}
	got := extractDomains(urls)
	want := map[string]bool{
		"evil.example.com": true,
		"good.com":         true,
		"files.test.net":   true,
	}
	if len(got) != len(want) {
		t.Errorf("extractDomains: got %d domains, want %d: %v", len(got), len(want), got)
	}
	for _, d := range got {
		if !want[d] {
			t.Errorf("extractDomains: unexpected domain %q", d)
		}
	}
}

func TestEncodeDomainChars(t *testing.T) {
	enc := encodeDomainChars("ab0-.", 10)
	want := []int64{1, 2, 27, 37, 38, 0, 0, 0, 0, 0}
	for i, v := range want {
		if enc[i] != v {
			t.Errorf("encodeDomainChars[%d]: got %d, want %d", i, enc[i], v)
		}
	}
}

func TestSoftmax2(t *testing.T) {
	p := softmax2(0, 0)
	if p < 0.49 || p > 0.51 {
		t.Errorf("softmax2(0,0) = %f, want ~0.5", p)
	}
	p2 := softmax2(-100, 100)
	if p2 < 0.999 {
		t.Errorf("softmax2(-100,100) = %f, want ~1.0", p2)
	}
}

func TestONNXScannerNoModelsDir(t *testing.T) {
	s, err := NewONNXScanner(&config.Config{}, slog.Default())
	if err != nil {
		t.Fatalf("NewONNXScanner: %v", err)
	}
	result := s.Scan(context.Background(), makeONNXTestEmail("hello", nil))
	if result.Verdict != "skip" {
		t.Errorf("expected skip, got %q", result.Verdict)
	}
}

// ── Benchmarks ────────────────────────────────────────────────────────────────
// These require real model files. Set MAILHOOK_ONNX_MODELS_DIR to enable.

func loadBenchScanner(b *testing.B) *ONNXScanner {
	b.Helper()
	dir := os.Getenv("MAILHOOK_ONNX_MODELS_DIR")
	if dir == "" {
		b.Skip("MAILHOOK_ONNX_MODELS_DIR not set — skipping ONNX benchmarks")
	}
	cfg := &config.Config{
		ONNXModelsDir:     dir,
		ONNXBERTThreshold: 0.85,
		ONNXDGAThreshold:  0.80,
	}
	s, err := NewONNXScanner(cfg, slog.Default())
	if err != nil {
		b.Fatalf("NewONNXScanner: %v", err)
	}
	b.Cleanup(s.Close)
	return s
}

var phishingBody = `Dear customer, your account has been suspended due to unusual
activity. Please verify your identity immediately to restore access.
Click here: http://secure-login-verify.xyz/account/restore`

func BenchmarkONNXScannerBERT(b *testing.B) {
	s := loadBenchScanner(b)
	email := makeONNXTestEmail(phishingBody, nil)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Scan(context.Background(), email)
	}
}

func BenchmarkONNXScannerDGA(b *testing.B) {
	s := loadBenchScanner(b)
	email := makeONNXTestEmail("", []string{
		"http://xkcd2019.com/path",
		"https://zzq8fk3m.ru/login",
	})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Scan(context.Background(), email)
	}
}

func BenchmarkONNXScannerClean(b *testing.B) {
	s := loadBenchScanner(b)
	email := makeONNXTestEmail("Hi Bob, see you tomorrow.", []string{"https://google.com/"})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Scan(context.Background(), email)
	}
}
