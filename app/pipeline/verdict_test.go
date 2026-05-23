package pipeline

import (
	"testing"
)

var defaultThresholds = Thresholds{SpamScore: 5.0, RejectScore: 15.0}

func TestDecide_MalwareBazaarHit(t *testing.T) {
	email := &Email{}
	results := []ScanResult{
		{Scanner: "malwarebazaar", Verdict: "malicious", Score: 1.0, Detail: "MalwareBazaar: 1 attachment(s) matched feed"},
	}
	vd := Decide(defaultThresholds, email, results)
	if vd.Verdict != "MALWARE" {
		t.Errorf("want MALWARE, got %s", vd.Verdict)
	}
	if vd.Decision != "delete" {
		t.Errorf("want delete, got %s", vd.Decision)
	}
	if vd.Confidence != 0.88 {
		t.Errorf("want confidence 0.88, got %.2f", vd.Confidence)
	}
}

func TestDecide_VTTakesPriorityOverMB(t *testing.T) {
	email := &Email{}
	results := []ScanResult{
		{Scanner: "virustotal", Verdict: "malicious", Score: 5, Detail: "VT: 5/60"},
		{Scanner: "malwarebazaar", Verdict: "malicious", Score: 1.0, Detail: "MalwareBazaar: 1 attachment(s) matched feed"},
	}
	vd := Decide(defaultThresholds, email, results)
	if vd.Verdict != "MALWARE" {
		t.Errorf("want MALWARE, got %s", vd.Verdict)
	}
	if vd.Confidence != 0.90 {
		t.Errorf("want VT confidence 0.90 (VT takes priority), got %.2f", vd.Confidence)
	}
}

func TestDecide_Clean(t *testing.T) {
	email := &Email{SPFResult: "pass", DKIMResult: "pass", DMARCResult: "pass"}
	results := []ScanResult{
		{Scanner: "rspamd", Verdict: "clean", Score: 1.0},
		{Scanner: "clamav", Verdict: "clean"},
		{Scanner: "yara", Verdict: "clean"},
		{Scanner: "urlcheck", Verdict: "clean"},
		{Scanner: "ipreputation", Verdict: "clean"},
		{Scanner: "virustotal", Verdict: "clean"},
	}
	vd := Decide(defaultThresholds, email, results)
	if vd.Verdict != "CLEAN" {
		t.Errorf("expected CLEAN, got %s", vd.Verdict)
	}
	if vd.Decision != "pass" {
		t.Errorf("expected pass, got %s", vd.Decision)
	}
	if vd.Confidence != 1.0 {
		t.Errorf("expected confidence 1.0, got %.2f", vd.Confidence)
	}
}

func TestDecide_ClamAVMalware(t *testing.T) {
	email := &Email{}
	results := []ScanResult{
		{Scanner: "clamav", Verdict: "malicious", Detail: "Eicar.Test.Virus"},
	}
	vd := Decide(defaultThresholds, email, results)
	if vd.Verdict != "MALWARE" {
		t.Errorf("expected MALWARE, got %s", vd.Verdict)
	}
	if vd.Decision != "delete" {
		t.Errorf("expected delete, got %s", vd.Decision)
	}
	if vd.Confidence < 0.95 {
		t.Errorf("expected high confidence, got %.2f", vd.Confidence)
	}
}

func TestDecide_YARAMalware(t *testing.T) {
	email := &Email{}
	results := []ScanResult{
		{Scanner: "yara", Verdict: "malicious", Detail: "Backdoor_Generic"},
	}
	vd := Decide(defaultThresholds, email, results)
	if vd.Verdict != "MALWARE" {
		t.Errorf("expected MALWARE, got %s", vd.Verdict)
	}
	if vd.Decision != "delete" {
		t.Errorf("expected delete, got %s", vd.Decision)
	}
}

func TestDecide_VTMalware_HighCount(t *testing.T) {
	email := &Email{}
	results := []ScanResult{
		{Scanner: "virustotal", Verdict: "malicious", Score: 5, Detail: "5/72 engines"},
	}
	vd := Decide(defaultThresholds, email, results)
	if vd.Verdict != "MALWARE" {
		t.Errorf("expected MALWARE for VT>=3, got %s", vd.Verdict)
	}
}

func TestDecide_VTMalware_LowCount(t *testing.T) {
	email := &Email{}
	results := []ScanResult{
		{Scanner: "virustotal", Verdict: "malicious", Score: 1, Detail: "1/72"},
		{Scanner: "ipreputation", Verdict: "suspicious", Detail: "AbuseScore:40"},
	}
	// Two suspicious signals → SUSPICIOUS flag
	vd := Decide(defaultThresholds, email, results)
	if vd.Verdict != "SUSPICIOUS" {
		t.Errorf("expected SUSPICIOUS for 2 weak signals, got %s", vd.Verdict)
	}
}

func TestDecide_RspamdReject(t *testing.T) {
	email := &Email{SPFResult: "pass"}
	results := []ScanResult{
		{Scanner: "rspamd", Verdict: "reject", Score: 20.0},
	}
	vd := Decide(defaultThresholds, email, results)
	if vd.Verdict != "SPAM" {
		t.Errorf("expected SPAM, got %s", vd.Verdict)
	}
	if vd.Decision != "delete" {
		t.Errorf("expected delete for reject score, got %s", vd.Decision)
	}
}

func TestDecide_RspamdSpam(t *testing.T) {
	email := &Email{SPFResult: "pass"}
	results := []ScanResult{
		{Scanner: "rspamd", Verdict: "spam", Score: 8.0},
	}
	vd := Decide(defaultThresholds, email, results)
	if vd.Verdict != "SPAM" {
		t.Errorf("expected SPAM, got %s", vd.Verdict)
	}
	if vd.Decision != "quarantine" {
		t.Errorf("expected quarantine, got %s", vd.Decision)
	}
}

func TestDecide_PhishURL(t *testing.T) {
	email := &Email{}
	results := []ScanResult{
		{Scanner: "urlcheck", Verdict: "malicious", Detail: "urlhaus: https://evil.com"},
	}
	vd := Decide(defaultThresholds, email, results)
	if vd.Verdict != "PHISH" {
		t.Errorf("expected PHISH, got %s", vd.Verdict)
	}
	if vd.Decision != "quarantine" {
		t.Errorf("expected quarantine, got %s", vd.Decision)
	}
}

func TestDecide_ExecutableAttachment(t *testing.T) {
	email := &Email{
		HasExecutable: true,
		Attachments: []Attachment{
			{Filename: "virus.exe", Extension: ".exe", IsDangerous: true},
		},
	}
	results := []ScanResult{
		{Scanner: "rspamd", Verdict: "clean", Score: 1.0},
	}
	vd := Decide(defaultThresholds, email, results)
	if vd.Verdict != "SUSPICIOUS" {
		t.Errorf("expected SUSPICIOUS for exe attachment, got %s", vd.Verdict)
	}
	if vd.Decision != "quarantine" {
		t.Errorf("expected quarantine, got %s", vd.Decision)
	}
}

func TestDecide_AllAuthFail_SingleSignal(t *testing.T) {
	email := &Email{
		SPFResult:   "fail",
		DKIMResult:  "fail",
		DMARCResult: "fail",
	}
	results := []ScanResult{
		{Scanner: "rspamd", Verdict: "clean", Score: 2.0},
	}
	vd := Decide(defaultThresholds, email, results)
	// Only one suspicious reason → flag (not quarantine)
	if vd.Decision != "flag" {
		t.Errorf("expected flag for single suspicious signal, got %s", vd.Decision)
	}
}

func TestDecide_AllAuthFail_PlusSuspiciousIP(t *testing.T) {
	email := &Email{
		SPFResult:   "fail",
		DKIMResult:  "fail",
		DMARCResult: "fail",
	}
	results := []ScanResult{
		{Scanner: "ipreputation", Verdict: "suspicious", Detail: "abuse score 60"},
	}
	vd := Decide(defaultThresholds, email, results)
	if vd.Verdict != "SUSPICIOUS" {
		t.Errorf("expected SUSPICIOUS for auth fail + IP suspicious, got %s", vd.Verdict)
	}
	if vd.Decision != "quarantine" {
		t.Errorf("expected quarantine, got %s", vd.Decision)
	}
}

func TestDecide_IPMalicious(t *testing.T) {
	email := &Email{}
	results := []ScanResult{
		{Scanner: "ipreputation", Verdict: "malicious", Detail: "known botnet"},
	}
	vd := Decide(defaultThresholds, email, results)
	if vd.Verdict != "MALWARE" {
		t.Errorf("expected MALWARE for malicious IP, got %s", vd.Verdict)
	}
}

func TestDecide_ClamAVWins_OverRspamd(t *testing.T) {
	// ClamAV malware hit should take priority over spam score
	email := &Email{}
	results := []ScanResult{
		{Scanner: "rspamd", Verdict: "spam", Score: 20.0},
		{Scanner: "clamav", Verdict: "malicious", Detail: "Trojan.Generic"},
	}
	vd := Decide(defaultThresholds, email, results)
	if vd.Verdict != "MALWARE" {
		t.Errorf("ClamAV should win over Rspamd, got %s", vd.Verdict)
	}
	if vd.Decision != "delete" {
		t.Errorf("expected delete, got %s", vd.Decision)
	}
}

func TestDecide_CriticalScannerError_Quarantines(t *testing.T) {
	// ClamAV, YARA, or rspamd returning "error" (unavailable/timeout) must quarantine
	// (fail-closed). "skip" means the scanner is deliberately disabled, not failed.
	email := &Email{SPFResult: "pass", DKIMResult: "pass", DMARCResult: "pass"}
	for _, scanner := range []string{"clamav", "yara", "rspamd"} {
		results := []ScanResult{{Scanner: scanner, Verdict: "error"}}
		vd := Decide(defaultThresholds, email, results)
		if vd.Verdict != "SUSPICIOUS" || vd.Decision != "quarantine" {
			t.Errorf("scanner=%s verdict=error: expected SUSPICIOUS/quarantine, got %s/%s",
				scanner, vd.Verdict, vd.Decision)
		}
	}
}

func TestDecide_CriticalScannerSkip_Passes(t *testing.T) {
	// "skip" means deliberately disabled — not a failure, should not quarantine.
	email := &Email{SPFResult: "pass", DKIMResult: "pass", DMARCResult: "pass"}
	for _, scanner := range []string{"clamav", "yara", "rspamd"} {
		results := []ScanResult{{Scanner: scanner, Verdict: "skip", Detail: "disabled"}}
		vd := Decide(defaultThresholds, email, results)
		if vd.Decision == "quarantine" {
			t.Errorf("scanner=%s verdict=skip (disabled): should not quarantine, got %s/%s",
				scanner, vd.Verdict, vd.Decision)
		}
	}
}

func TestDecide_NonCriticalScannerError_Passes(t *testing.T) {
	// Errors on non-critical scanners (urlcheck, virustotal, ipreputation)
	// should not quarantine on their own.
	email := &Email{SPFResult: "pass", DKIMResult: "pass", DMARCResult: "pass"}
	results := []ScanResult{
		{Scanner: "urlcheck", Verdict: "error"},
		{Scanner: "virustotal", Verdict: "skip"},
		{Scanner: "ipreputation", Verdict: "error"},
	}
	vd := Decide(defaultThresholds, email, results)
	if vd.Verdict != "CLEAN" {
		t.Errorf("expected CLEAN for non-critical scanner errors, got %s", vd.Verdict)
	}
}

func TestDecide_RspamdAtExactSpamThreshold(t *testing.T) {
	email := &Email{SPFResult: "pass"}
	results := []ScanResult{
		{Scanner: "rspamd", Score: 5.0},
	}
	vd := Decide(defaultThresholds, email, results)
	if vd.Verdict != "SPAM" {
		t.Errorf("expected SPAM at exact spam threshold, got %s", vd.Verdict)
	}
}

func TestDecide_RspamdBelowSpamThreshold(t *testing.T) {
	email := &Email{SPFResult: "pass"}
	results := []ScanResult{
		{Scanner: "rspamd", Score: 4.9},
	}
	vd := Decide(defaultThresholds, email, results)
	if vd.Verdict != "CLEAN" {
		t.Errorf("expected CLEAN just below spam threshold, got %s", vd.Verdict)
	}
}

func TestScaleConfidence(t *testing.T) {
	cases := []struct {
		score, low, high float64
		want             float64
	}{
		{5.0, 5.0, 15.0, 0.70},
		{15.0, 5.0, 15.0, 0.99},
		{10.0, 5.0, 15.0, 0.845},
		{20.0, 5.0, 15.0, 0.99}, // clamped at max
	}
	for _, tc := range cases {
		got := scaleConfidence(tc.score, tc.low, tc.high)
		if got < tc.want-0.01 || got > tc.want+0.01 {
			t.Errorf("scaleConfidence(%.1f, %.1f, %.1f) = %.3f, want ~%.3f",
				tc.score, tc.low, tc.high, got, tc.want)
		}
	}
}

func TestDecide_NRDSuspiciousAlone(t *testing.T) {
	// NRD alone → flag (1 suspicious reason, not enough for quarantine)
	email := &Email{SPFResult: "pass", DKIMResult: "pass", DMARCResult: "pass"}
	results := []ScanResult{
		{Scanner: "rspamd", Verdict: "clean", Score: 1.0},
		{Scanner: "clamav", Verdict: "clean"},
		{Scanner: "yara", Verdict: "clean"},
		{Scanner: "urlcheck", Verdict: "clean"},
		{Scanner: "urlunshorten", Verdict: "clean"},
		{Scanner: "nrdcheck", Verdict: "suspicious", Score: 0.6, Detail: "newphish.xyz (3d old)"},
		{Scanner: "ipreputation", Verdict: "clean"},
		{Scanner: "virustotal", Verdict: "clean"},
	}
	vd := Decide(defaultThresholds, email, results)
	if vd.Decision != "flag" {
		t.Errorf("expected flag for NRD alone, got %s", vd.Decision)
	}
	if vd.Verdict != "SUSPICIOUS" {
		t.Errorf("expected SUSPICIOUS, got %s", vd.Verdict)
	}
}

func TestDecide_NRDPlusAuthFail_Quarantine(t *testing.T) {
	// NRD + all auth fail → 2 reasons → quarantine
	email := &Email{SPFResult: "fail", DKIMResult: "fail", DMARCResult: "fail"}
	results := []ScanResult{
		{Scanner: "rspamd", Verdict: "clean", Score: 1.0},
		{Scanner: "clamav", Verdict: "clean"},
		{Scanner: "yara", Verdict: "clean"},
		{Scanner: "urlcheck", Verdict: "clean"},
		{Scanner: "urlunshorten", Verdict: "clean"},
		{Scanner: "nrdcheck", Verdict: "suspicious", Score: 0.6, Detail: "newphish.xyz (2d old)"},
		{Scanner: "ipreputation", Verdict: "clean"},
		{Scanner: "virustotal", Verdict: "clean"},
	}
	vd := Decide(defaultThresholds, email, results)
	if vd.Decision != "quarantine" {
		t.Errorf("expected quarantine for NRD+authfail, got %s", vd.Decision)
	}
	if vd.Verdict != "SUSPICIOUS" {
		t.Errorf("expected SUSPICIOUS, got %s", vd.Verdict)
	}
}

func TestDecide_NRDPlusIPSuspicious_Quarantine(t *testing.T) {
	// NRD + suspicious IP → 2 reasons → quarantine
	email := &Email{SPFResult: "pass", DKIMResult: "pass", DMARCResult: "pass"}
	results := []ScanResult{
		{Scanner: "rspamd", Verdict: "clean", Score: 1.0},
		{Scanner: "clamav", Verdict: "clean"},
		{Scanner: "yara", Verdict: "clean"},
		{Scanner: "urlcheck", Verdict: "clean"},
		{Scanner: "urlunshorten", Verdict: "clean"},
		{Scanner: "nrdcheck", Verdict: "suspicious", Score: 0.6, Detail: "newphish.xyz (1d old)"},
		{Scanner: "ipreputation", Verdict: "suspicious", Detail: "abuse score 42"},
		{Scanner: "virustotal", Verdict: "clean"},
	}
	vd := Decide(defaultThresholds, email, results)
	if vd.Decision != "quarantine" {
		t.Errorf("expected quarantine for NRD+IP suspicious, got %s", vd.Decision)
	}
}

func TestDecide_URLUnshortenMalicious(t *testing.T) {
	// urlunshorten malicious → Priority 3 (PHISH/quarantine), same path as urlcheck
	email := &Email{SPFResult: "pass", DKIMResult: "pass", DMARCResult: "pass"}
	results := []ScanResult{
		{Scanner: "rspamd", Verdict: "clean", Score: 1.0},
		{Scanner: "clamav", Verdict: "clean"},
		{Scanner: "yara", Verdict: "clean"},
		{Scanner: "urlcheck", Verdict: "clean"},
		{Scanner: "urlunshorten", Verdict: "malicious", Detail: "http://evil.com/payload"},
		{Scanner: "nrdcheck", Verdict: "clean"},
		{Scanner: "ipreputation", Verdict: "clean"},
		{Scanner: "virustotal", Verdict: "clean"},
	}
	vd := Decide(defaultThresholds, email, results)
	if vd.Decision != "quarantine" {
		t.Errorf("expected quarantine for urlunshorten malicious, got %s", vd.Decision)
	}
	if vd.Verdict != "PHISH" {
		t.Errorf("expected PHISH, got %s", vd.Verdict)
	}
	if vd.Confidence != 0.97 {
		t.Errorf("expected confidence 0.97, got %f", vd.Confidence)
	}
}

func TestDecide_URLUnshortenPlusNRD_URLWins(t *testing.T) {
	// urlunshorten hit (Priority 3) fires before NRD (Priority 6)
	email := &Email{SPFResult: "pass", DKIMResult: "pass", DMARCResult: "pass"}
	results := []ScanResult{
		{Scanner: "rspamd", Verdict: "clean", Score: 1.0},
		{Scanner: "clamav", Verdict: "clean"},
		{Scanner: "yara", Verdict: "clean"},
		{Scanner: "urlcheck", Verdict: "clean"},
		{Scanner: "urlunshorten", Verdict: "malicious", Detail: "http://evil.com/payload"},
		{Scanner: "nrdcheck", Verdict: "suspicious", Score: 0.6, Detail: "evil.com (1d old)"},
		{Scanner: "ipreputation", Verdict: "clean"},
		{Scanner: "virustotal", Verdict: "clean"},
	}
	vd := Decide(defaultThresholds, email, results)
	// urlunshorten (Priority 3) wins — verdict is PHISH not SUSPICIOUS
	if vd.Verdict != "PHISH" {
		t.Errorf("expected PHISH (urlunshorten wins over NRD), got %s", vd.Verdict)
	}
	if vd.Decision != "quarantine" {
		t.Errorf("expected quarantine, got %s", vd.Decision)
	}
}

func TestDecide_HTMLSmuggling_Quarantine(t *testing.T) {
	// HTML smuggling alone → Priority 5.5 → quarantine SUSPICIOUS
	email := &Email{SPFResult: "pass", DKIMResult: "pass", DMARCResult: "pass"}
	results := []ScanResult{
		{Scanner: "rspamd", Verdict: "clean", Score: 1.0},
		{Scanner: "clamav", Verdict: "clean"},
		{Scanner: "yara", Verdict: "clean"},
		{Scanner: "urlcheck", Verdict: "clean"},
		{Scanner: "urlunshorten", Verdict: "clean"},
		{Scanner: "nrdcheck", Verdict: "clean"},
		{Scanner: "ipreputation", Verdict: "clean"},
		{Scanner: "virustotal", Verdict: "clean"},
		{Scanner: "htmlsmuggling", Verdict: "suspicious", Score: 0.80, Detail: "HTML smuggling: body: new Blob("},
		{Scanner: "hiddentextdetect", Verdict: "clean"},
	}
	vd := Decide(defaultThresholds, email, results)
	if vd.Verdict != "SUSPICIOUS" {
		t.Errorf("expected SUSPICIOUS for HTML smuggling, got %s", vd.Verdict)
	}
	if vd.Decision != "quarantine" {
		t.Errorf("expected quarantine for HTML smuggling, got %s", vd.Decision)
	}
	if vd.Confidence != 0.80 {
		t.Errorf("expected confidence 0.80, got %f", vd.Confidence)
	}
}

func TestDecide_HTMLSmuggling_BeatsLowerPriority(t *testing.T) {
	// HTML smuggling (Priority 5.5) fires before Priority 6 suspicious signals
	email := &Email{SPFResult: "fail", DKIMResult: "fail", DMARCResult: "fail"}
	results := []ScanResult{
		{Scanner: "rspamd", Verdict: "clean", Score: 1.0},
		{Scanner: "clamav", Verdict: "clean"},
		{Scanner: "yara", Verdict: "clean"},
		{Scanner: "urlcheck", Verdict: "clean"},
		{Scanner: "urlunshorten", Verdict: "clean"},
		{Scanner: "nrdcheck", Verdict: "clean"},
		{Scanner: "ipreputation", Verdict: "clean"},
		{Scanner: "virustotal", Verdict: "clean"},
		{Scanner: "htmlsmuggling", Verdict: "suspicious", Score: 0.80, Detail: "HTML smuggling: body: new Blob("},
		{Scanner: "hiddentextdetect", Verdict: "clean"},
	}
	vd := Decide(defaultThresholds, email, results)
	if vd.Decision != "quarantine" {
		t.Errorf("expected quarantine (Priority 5.5 wins), got %s", vd.Decision)
	}
	if vd.Confidence != 0.80 {
		t.Errorf("expected confidence 0.80, got %f", vd.Confidence)
	}
}

func TestDecide_HiddenTextAlone_Flag(t *testing.T) {
	// Hidden text alone → 1 suspicious signal → flag, not quarantine
	email := &Email{SPFResult: "pass", DKIMResult: "pass", DMARCResult: "pass"}
	results := []ScanResult{
		{Scanner: "rspamd", Verdict: "clean", Score: 1.0},
		{Scanner: "clamav", Verdict: "clean"},
		{Scanner: "yara", Verdict: "clean"},
		{Scanner: "urlcheck", Verdict: "clean"},
		{Scanner: "urlunshorten", Verdict: "clean"},
		{Scanner: "nrdcheck", Verdict: "clean"},
		{Scanner: "ipreputation", Verdict: "clean"},
		{Scanner: "virustotal", Verdict: "clean"},
		{Scanner: "htmlsmuggling", Verdict: "clean"},
		{Scanner: "hiddentextdetect", Verdict: "suspicious", Score: 0.50, Detail: "hidden text: zero_font"},
	}
	vd := Decide(defaultThresholds, email, results)
	if vd.Decision != "flag" {
		t.Errorf("expected flag for hidden text alone, got %s", vd.Decision)
	}
	if vd.Verdict != "SUSPICIOUS" {
		t.Errorf("expected SUSPICIOUS, got %s", vd.Verdict)
	}
}

func TestDecide_HiddenTextPlusAuthFail_Quarantine(t *testing.T) {
	// Hidden text + all-auth-fail → 2 suspicious signals → quarantine
	email := &Email{SPFResult: "fail", DKIMResult: "fail", DMARCResult: "fail"}
	results := []ScanResult{
		{Scanner: "rspamd", Verdict: "clean", Score: 1.0},
		{Scanner: "clamav", Verdict: "clean"},
		{Scanner: "yara", Verdict: "clean"},
		{Scanner: "urlcheck", Verdict: "clean"},
		{Scanner: "urlunshorten", Verdict: "clean"},
		{Scanner: "nrdcheck", Verdict: "clean"},
		{Scanner: "ipreputation", Verdict: "clean"},
		{Scanner: "virustotal", Verdict: "clean"},
		{Scanner: "htmlsmuggling", Verdict: "clean"},
		{Scanner: "hiddentextdetect", Verdict: "suspicious", Score: 0.50, Detail: "hidden text: display_none"},
	}
	vd := Decide(defaultThresholds, email, results)
	if vd.Decision != "quarantine" {
		t.Errorf("expected quarantine for hidden text + auth fail, got %s", vd.Decision)
	}
	if vd.Verdict != "SUSPICIOUS" {
		t.Errorf("expected SUSPICIOUS, got %s", vd.Verdict)
	}
}

func TestDecide_HiddenTextPlusNRD_Quarantine(t *testing.T) {
	// Hidden text + NRD hit → 2 suspicious signals → quarantine
	email := &Email{SPFResult: "pass", DKIMResult: "pass", DMARCResult: "pass"}
	results := []ScanResult{
		{Scanner: "rspamd", Verdict: "clean", Score: 1.0},
		{Scanner: "clamav", Verdict: "clean"},
		{Scanner: "yara", Verdict: "clean"},
		{Scanner: "urlcheck", Verdict: "clean"},
		{Scanner: "urlunshorten", Verdict: "clean"},
		{Scanner: "nrdcheck", Verdict: "suspicious", Score: 0.6, Detail: "newspam.xyz (4d old)"},
		{Scanner: "ipreputation", Verdict: "clean"},
		{Scanner: "virustotal", Verdict: "clean"},
		{Scanner: "htmlsmuggling", Verdict: "clean"},
		{Scanner: "hiddentextdetect", Verdict: "suspicious", Score: 0.50, Detail: "hidden text: zero_font, display_none"},
	}
	vd := Decide(defaultThresholds, email, results)
	if vd.Decision != "quarantine" {
		t.Errorf("expected quarantine for hidden text + NRD, got %s", vd.Decision)
	}
}

func TestDecide_HTMLSmuggling_WinsOverPriority6(t *testing.T) {
	// HTML smuggling (P5.5) fires before Priority 6 with 2+ signals
	email := &Email{SPFResult: "fail", DKIMResult: "fail", DMARCResult: "fail"}
	results := []ScanResult{
		{Scanner: "rspamd", Verdict: "clean", Score: 1.0},
		{Scanner: "clamav", Verdict: "clean"},
		{Scanner: "yara", Verdict: "clean"},
		{Scanner: "urlcheck", Verdict: "clean"},
		{Scanner: "urlunshorten", Verdict: "clean"},
		{Scanner: "nrdcheck", Verdict: "suspicious", Score: 0.6, Detail: "newevil.xyz (1d old)"},
		{Scanner: "ipreputation", Verdict: "suspicious", Detail: "abuse score 50"},
		{Scanner: "virustotal", Verdict: "clean"},
		{Scanner: "htmlsmuggling", Verdict: "suspicious", Score: 0.80, Detail: "HTML smuggling: attachment:payload.html: new Blob("},
		{Scanner: "hiddentextdetect", Verdict: "clean"},
	}
	vd := Decide(defaultThresholds, email, results)
	if vd.Confidence != 0.80 {
		t.Errorf("expected HTML smuggling confidence 0.80 (not P6 confidence 0.60), got %f", vd.Confidence)
	}
}
