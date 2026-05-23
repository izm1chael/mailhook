package pipeline

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ScanResult is returned by each scanner. Verdict values signal the pipeline
// what kind of threat (if any) was found.
type ScanResult struct {
	Scanner string
	Verdict string // clean | suspicious | malicious | error | skip
	Score   float64
	Detail  string
	Matches json.RawMessage // structured scanner payload (scanner-specific)
}

// VerdictDecision is the final action the pipeline should take.
type VerdictDecision struct {
	Decision  string  // pass | quarantine | delete | flag
	Reason    string
	Verdict   string  // CLEAN | SPAM | PHISH | MALWARE | SUSPICIOUS
	Confidence float64 // 0.0–1.0
	Results   []ScanResult
}

// Thresholds holds the configurable scoring thresholds used by Decide.
type Thresholds struct {
	SpamScore   float64
	RejectScore float64
}

// Decide applies verdict rules to the collected scan results and returns the
// final action for the pipeline to take. Rules are applied in priority order —
// the first matching rule wins.
func Decide(t Thresholds, email *Email, results []ScanResult) VerdictDecision {
	// Collect signals from results
	var (
		rspamdScore         float64
		clamHit             bool
		clamDetail          string
		yaraHit             bool
		yaraDetail          string
		urlHit              bool
		urlDetail           string
		vtPositives         int
		vtDetail            string
		mbHit               bool
		mbDetail            string
		ipSuspicious        bool
		ipMalicious         bool
		ipDetail            string
		nrdHit              bool
		nrdDetail           string
		htmlSmugglingHit    bool
		htmlSmugglingDetail string
		hiddenTextHit       bool
		hiddenTextDetail    string
		onnxMalicious       bool
		onnxSuspicious      bool
		onnxDetail          string
	)

	for _, r := range results {
		switch r.Scanner {
		case "rspamd":
			rspamdScore = r.Score
		case "clamav":
			if r.Verdict == "malicious" {
				clamHit = true
				clamDetail = r.Detail
			}
		case "yara":
			if r.Verdict == "malicious" {
				yaraHit = true
				yaraDetail = r.Detail
			}
		case "urlcheck":
			if r.Verdict == "malicious" || r.Verdict == "suspicious" {
				urlHit = true
				urlDetail = r.Detail
			}
		case "urlunshorten":
			if r.Verdict == "malicious" {
				urlHit = true
				urlDetail = r.Detail
			}
		case "nrdcheck":
			if r.Verdict == "suspicious" {
				nrdHit = true
				nrdDetail = r.Detail
			}
		case "htmlsmuggling":
			if r.Verdict == "suspicious" {
				htmlSmugglingHit = true
				htmlSmugglingDetail = r.Detail
			}
		case "hiddentextdetect":
			if r.Verdict == "suspicious" {
				hiddenTextHit = true
				hiddenTextDetail = r.Detail
			}
		case "virustotal":
			if r.Verdict == "malicious" {
				vtPositives = int(r.Score)
				vtDetail = r.Detail
			}
		case "malwarebazaar":
			if r.Verdict == "malicious" {
				mbHit = true
				mbDetail = r.Detail
			}
		case "ipreputation":
			if r.Verdict == "malicious" {
				ipMalicious = true
				ipDetail = r.Detail
			} else if r.Verdict == "suspicious" {
				ipSuspicious = true
				ipDetail = r.Detail
			}
		case "onnx":
			if r.Verdict == "malicious" {
				onnxMalicious = true
				onnxDetail = r.Detail
			} else if r.Verdict == "suspicious" {
				onnxSuspicious = true
				onnxDetail = r.Detail
			}
		}
	}

	// ── Priority 1: Definite malware ──────────────────────────────────────────
	if clamHit {
		return decided("delete", "MALWARE", fmt.Sprintf("ClamAV: %s", clamDetail), 0.99, results)
	}
	if yaraHit {
		return decided("delete", "MALWARE", fmt.Sprintf("YARA match: %s", yaraDetail), 0.95, results)
	}
	if vtPositives >= 3 {
		return decided("delete", "MALWARE", vtDetail, 0.90, results)
	}
	if mbHit {
		return decided("delete", "MALWARE", mbDetail, 0.88, results)
	}
	if ipMalicious {
		return decided("delete", "MALWARE", fmt.Sprintf("IP reputation: %s", ipDetail), 0.85, results)
	}

	// ── Priority 2: Rspamd reject score ──────────────────────────────────────
	if rspamdScore >= t.RejectScore {
		return decided("delete", "SPAM",
			fmt.Sprintf("Rspamd score %.1f ≥ reject threshold %.1f", rspamdScore, t.RejectScore),
			scaleConfidence(rspamdScore, t.SpamScore, t.RejectScore), results)
	}

	// ── Priority 3: Phishing URL (feed + AI) ─────────────────────────────────
	if urlHit {
		return decided("quarantine", "PHISH", fmt.Sprintf("URL threat feed match: %s", urlDetail), 0.97, results)
	}
	if onnxMalicious {
		return decided("quarantine", "PHISH", "AI phishing URL: "+onnxDetail, 0.87, results)
	}

	// ── Priority 4: Rspamd spam threshold ────────────────────────────────────
	if rspamdScore >= t.SpamScore {
		return decided("quarantine", "SPAM",
			fmt.Sprintf("Rspamd score %.1f ≥ spam threshold %.1f", rspamdScore, t.SpamScore),
			scaleConfidence(rspamdScore, t.SpamScore, t.RejectScore), results)
	}

	// ── Priority 5: Executable attachment ────────────────────────────────────
	if email.HasExecutable {
		exts := executableExtensions(email.Attachments)
		return decided("quarantine", "SUSPICIOUS",
			fmt.Sprintf("dangerous attachment extension(s): %s", strings.Join(exts, ", ")),
			0.70, results)
	}

	// ── Priority 5.5: HTML smuggling detected ────────────────────────────────
	if htmlSmugglingHit {
		return decided("quarantine", "SUSPICIOUS", htmlSmugglingDetail, 0.80, results)
	}

	// ── Priority 5.7: ONNX DGA suspicious ───────────────────────────────────
	if onnxSuspicious {
		// Suspicious DGA alone is not enough to quarantine, but combined with
		// auth failure or a newly registered domain it tips the balance.
		authOK := email.SPFResult == "pass" || email.DKIMResult == "pass" || email.DMARCResult == "pass"
		if !authOK || nrdHit {
			return decided("quarantine", "SUSPICIOUS", "AI DGA + auth/nrd: "+onnxDetail, 0.75, results)
		}
	}

	// ── Priority 6: Suspicious signals (require 2+) ──────────────────────────
	var suspiciousReasons []string
	allAuthFail := email.SPFResult != "pass" && email.DKIMResult != "pass" && email.DMARCResult != "pass"
	if allAuthFail {
		suspiciousReasons = append(suspiciousReasons, "SPF/DKIM/DMARC all failed")
	}
	if ipSuspicious {
		suspiciousReasons = append(suspiciousReasons, fmt.Sprintf("IP reputation: %s", ipDetail))
	}
	if vtPositives > 0 && vtPositives < 3 {
		suspiciousReasons = append(suspiciousReasons, fmt.Sprintf("VirusTotal: %d engine(s)", vtPositives))
	}
	if nrdHit {
		suspiciousReasons = append(suspiciousReasons, fmt.Sprintf("newly registered domain: %s", nrdDetail))
	}
	if hiddenTextHit {
		suspiciousReasons = append(suspiciousReasons, fmt.Sprintf("hidden text/zero-font: %s", hiddenTextDetail))
	}
	if len(suspiciousReasons) >= 2 {
		return decided("quarantine", "SUSPICIOUS", strings.Join(suspiciousReasons, "; "), 0.60, results)
	}
	if len(suspiciousReasons) == 1 {
		return decided("flag", "SUSPICIOUS", suspiciousReasons[0], 0.40, results)
	}

	// ── Fail-closed: critical scanner unavailable, errored, or timed out ────────
	// "skip" = scanner is deliberately disabled (no rules loaded). Not a failure.
	// "error" = scanner failed to run (unavailable daemon, timeout, decode error).
	// When a critical scanner returns "error", quarantine rather than pass — a
	// missing clamd/rspamd is not the same as a clean scan.
	criticalScanners := map[string]bool{"clamav": true, "yara": true, "rspamd": true}
	for _, r := range results {
		if criticalScanners[r.Scanner] && r.Verdict == "error" {
			return decided("quarantine", "SUSPICIOUS",
				fmt.Sprintf("%s scan failed or timed out — manual review required", r.Scanner),
				0.5, results)
		}
	}

	// ── Clean ─────────────────────────────────────────────────────────────────
	return decided("pass", "CLEAN", "No threats detected", 1.0, results)
}

func decided(decision, verdict, reason string, confidence float64, results []ScanResult) VerdictDecision {
	return VerdictDecision{
		Decision:   decision,
		Verdict:    verdict,
		Reason:     reason,
		Confidence: confidence,
		Results:    results,
	}
}

func scaleConfidence(score, low, high float64) float64 {
	if high <= low {
		return 0.70
	}
	ratio := (score - low) / (high - low)
	if ratio > 1 {
		return 0.99
	}
	return 0.70 + 0.29*ratio
}

func executableExtensions(atts []Attachment) []string {
	seen := make(map[string]bool)
	var exts []string
	for _, a := range atts {
		if a.IsDangerous && !seen[a.Extension] {
			seen[a.Extension] = true
			exts = append(exts, a.Extension)
		}
	}
	return exts
}
