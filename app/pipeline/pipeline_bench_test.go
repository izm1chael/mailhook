package pipeline_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/izm1chael/mailhook/pipeline"
)

// stubScanner is a minimal Scanner that returns immediately, used to measure
// pipeline orchestration overhead without real scanner latency.
type stubScanner struct {
	name    string
	verdict string
}

func (s *stubScanner) Name() string { return s.name }
func (s *stubScanner) Scan(_ context.Context, _ *pipeline.Email) pipeline.ScanResult {
	return pipeline.ScanResult{Scanner: s.name, Verdict: s.verdict, Score: 0}
}

func benchEmail() *pipeline.Email {
	return &pipeline.Email{
		IMAPUID:     1,
		AccountName: "bench",
		Subject:     "Test Subject",
		From:        "sender@example.com",
		To:          "recipient@example.com",
		TextBody:    "Hello, this is a test email for benchmarking pipeline throughput.",
		HTMLBody:    "<p>Hello, this is a test email.</p>",
		URLs:        []string{"https://example.com/link"},
		Date:        time.Now(),
		SPFResult:   "pass",
		DKIMResult:  "pass",
		DMARCResult: "pass",
		SenderIPs:   []net.IP{net.ParseIP("1.2.3.4")},
	}
}

// BenchmarkDecideClean measures the verdict engine with all-clean results from
// a realistic 12-scanner configuration (11 existing + ONNX stub).
func BenchmarkDecideClean(b *testing.B) {
	scannerNames := []string{
		"rspamd", "clamav", "yara", "urlcheck", "urlunshorten",
		"nrdcheck", "ipreputation", "virustotal", "htmlsmuggling",
		"hiddentextdetect", "malwarebazaar", "onnx",
	}
	results := make([]pipeline.ScanResult, len(scannerNames))
	for i, name := range scannerNames {
		results[i] = pipeline.ScanResult{Scanner: name, Verdict: "clean"}
	}
	t := pipeline.Thresholds{SpamScore: 5.0, RejectScore: 15.0}
	email := benchEmail()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pipeline.Decide(t, email, results)
	}
}

// BenchmarkDecidePhish measures the verdict path that hits the ONNX malicious rule.
func BenchmarkDecidePhish(b *testing.B) {
	results := []pipeline.ScanResult{
		{Scanner: "rspamd", Verdict: "clean", Score: 2.0},
		{Scanner: "clamav", Verdict: "clean"},
		{Scanner: "yara", Verdict: "clean"},
		{Scanner: "urlcheck", Verdict: "clean"},
		{Scanner: "urlunshorten", Verdict: "clean"},
		{Scanner: "nrdcheck", Verdict: "clean"},
		{Scanner: "ipreputation", Verdict: "clean"},
		{Scanner: "virustotal", Verdict: "clean"},
		{Scanner: "htmlsmuggling", Verdict: "clean"},
		{Scanner: "hiddentextdetect", Verdict: "clean"},
		{Scanner: "malwarebazaar", Verdict: "clean"},
		{Scanner: "onnx", Verdict: "malicious", Score: 0.92, Detail: "bert_phish=0.920"},
	}
	t := pipeline.Thresholds{SpamScore: 5.0, RejectScore: 15.0}
	email := benchEmail()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pipeline.Decide(t, email, results)
	}
}
