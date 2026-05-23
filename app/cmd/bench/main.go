// bench hits both the standard and AI MailHook instances with generated EML
// and compares verdicts + measures scanner latency side by side.
//
// Prerequisites:
//
//	docker compose -f docker-compose.bench.yml up -d
//	(wait for health endpoints to return {"status":"healthy"})
//
// Usage:
//
//	go run ./cmd/bench/                                     # 50 scenarios, both on localhost
//	go run ./cmd/bench/ -n 100 -seed 42                    # reproducible 100-scenario run
//	go run ./cmd/bench/ -std http://std:8080 -ai http://ai:8081
//	go run ./cmd/bench/ -n 20 -format json                 # machine-readable output
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"flag"
	"net/url"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"
)

// ─── PRNG (same xorshift64 as cmd/simulate/gen.go) ───────────────────────────

type prng struct{ state uint64 }

func newPRNG(seed uint64) *prng {
	if seed == 0 {
		var b [8]byte
		if _, err := rand.Read(b[:]); err != nil {
			seed = 0xdeadbeefcafe1234
		} else {
			seed = binary.LittleEndian.Uint64(b[:])
		}
	}
	if seed == 0 {
		seed = 1
	}
	return &prng{state: seed}
}

func (p *prng) next() uint64 {
	p.state ^= p.state << 13
	p.state ^= p.state >> 7
	p.state ^= p.state << 17
	return p.state
}

func (p *prng) Intn(n int) int   { return int(p.next() % uint64(n)) }
func (p *prng) Float64() float64 { return float64(p.next()>>11) / (1 << 53) }
func (p *prng) pick(s []string) string { return s[p.Intn(len(s))] }

// ─── EML builder ─────────────────────────────────────────────────────────────

// buildEML constructs a minimal but parseable EML from the given fields.
// URLs are embedded in the body as plain-text links so the URL extractor picks them up.
func buildEML(from, to, subject, spf, dkim, dmarc, body string, urls []string) []byte {
	var sb strings.Builder
	sb.WriteString("From: " + from + "\r\n")
	sb.WriteString("To: " + to + "\r\n")
	sb.WriteString("Subject: " + subject + "\r\n")
	sb.WriteString(fmt.Sprintf(
		"Authentication-Results: mx.bench.test; spf=%s smtp.mailfrom=%s; dkim=%s; dmarc=%s\r\n",
		spf, from, dkim, dmarc,
	))
	sb.WriteString("MIME-Version: 1.0\r\n")
	sb.WriteString("Content-Type: text/plain; charset=utf-8\r\n\r\n")
	sb.WriteString(body)
	if len(urls) > 0 {
		sb.WriteString("\r\n\r\n")
		for _, u := range urls {
			sb.WriteString(u + "\r\n")
		}
	}
	return []byte(sb.String())
}

// ─── Email generators ─────────────────────────────────────────────────────────

var (
	firstNames    = []string{"Michael", "Sarah", "James", "Emily", "Robert", "Jennifer", "David", "Lisa"}
	lastNames     = []string{"Chen", "Williams", "Johnson", "Smith", "Brown", "Jones", "Garcia", "Miller"}
	companyNames  = []string{"Acme Corp", "GlobalTech Inc", "Meridian Holdings", "Apex Solutions", "Sterling Group"}
	execTitles    = []string{"CEO", "CFO", "CTO", "VP Finance", "Managing Director"}
	becUrgency    = []string{
		"This must be completed before close of business today.",
		"I am in back-to-back meetings and cannot take calls.",
		"Do not discuss this with anyone else.",
		"This is time-sensitive — the window closes at 3pm.",
	}
	becPurposes = []string{"a confidential acquisition", "a legal settlement", "a vendor advance payment", "an escrow requirement"}

	phishBrands = []struct{ name, domain string }{
		{"PayPal", "paypa1-secure.com"},
		{"Microsoft", "microsoft-account-alert.com"},
		{"Amazon", "amaz0n-verify.net"},
		{"Apple", "apple-id-verify.com"},
		{"Netflix", "netflix-billing-update.com"},
		{"DHL", "dhl-delivery-notification.com"},
	}
	phishUrgency = []string{
		"Your account has been limited due to suspicious activity. Verify within 24 hours or be permanently suspended.",
		"We detected an unauthorised sign-in. Confirm your identity immediately to secure your account.",
		"Your payment information is out of date. Update billing details within 48 hours.",
		"Unusual activity detected. Click below to verify your identity and restore full access.",
	}

	dgaTLDs    = []string{".top", ".xyz", ".ru", ".tk", ".pw", ".cc", ".biz", ".info", ".site", ".online"}
	dgaChars   = "abcdefghijklmnopqrstuvwxyz0123456789"
	dgaBeacons = []string{"/verify/account", "/secure/login", "/gate.php", "/beacon", "/cmd"}

	cleanSubjects = []string{"Weekly Tech Digest", "Your Order Has Shipped", "Meeting Reminder", "Monthly Newsletter", "Team Update"}
	cleanSenders  = []string{
		"digest@techcrunch-news.example.com", "noreply@amazon.com",
		"calendar@google.com", "newsletter@github.com",
	}
	cleanBodies = []string{
		"This week in tech: new AI releases, cloud updates, and open-source highlights.",
		"Your order has been shipped and is on its way. Track it with the link below.",
		"Reminder: your weekly team standup is tomorrow at 10am.",
		"Here are the top articles from our community this month.",
	}
)

type benchEmail struct {
	name     string
	category string
	eml      []byte
}

func (p *prng) dgaDomain() string {
	n := 8 + p.Intn(5)
	var b strings.Builder
	for range n {
		b.WriteByte(dgaChars[p.Intn(len(dgaChars))])
	}
	return b.String() + p.pick(dgaTLDs)
}

func (p *prng) fullName() string {
	return p.pick(firstNames) + " " + p.pick(lastNames)
}

func (p *prng) genBEC(n int) benchEmail {
	exec := p.fullName()
	title := p.pick(execTitles)
	company := p.pick(companyNames)
	amount := fmt.Sprintf("$%d,000", 10+p.Intn(490))
	purpose := p.pick(becPurposes)
	urgency := p.pick(becUrgency)
	recipient := p.pick(firstNames)
	fromDomain := strings.ToLower(strings.ReplaceAll(company, " ", "")) + ".com"

	body := fmt.Sprintf(
		"%s,\n\nI need you to process an urgent wire transfer of %s for %s.\n%s\n"+
			"Bank details will follow. Please confirm receipt immediately.\n\n%s — %s, %s",
		recipient, amount, purpose, urgency, exec, title, company,
	)
	return benchEmail{
		name:     fmt.Sprintf("bec-%d", n),
		category: "BEC",
		eml:      buildEML(exec+" <"+strings.ToLower(strings.ReplaceAll(exec, " ", "."))+"@"+fromDomain+">", "accounts@mailhook.test", "Urgent: Wire Transfer Request", "softfail", "fail", "fail", body, nil),
	}
}

func (p *prng) genPhish(n int) benchEmail {
	brand := phishBrands[p.Intn(len(phishBrands))]
	urgency := p.pick(phishUrgency)
	path := "/verify?token=" + fmt.Sprintf("%016x", p.next())
	url := "https://" + brand.domain + path
	body := brand.name + " Security Notice:\n\n" + urgency + "\n"
	return benchEmail{
		name:     fmt.Sprintf("phish-%d", n),
		category: "PHISH",
		eml:      buildEML("security@"+brand.domain, "customer@mailhook.test", "Action Required: "+brand.name+" Account", "fail", "fail", "fail", body, []string{url}),
	}
}

func (p *prng) genDGA(n int) benchEmail {
	d1, d2 := p.dgaDomain(), p.dgaDomain()
	beacon := p.pick(dgaBeacons)
	body := "Please verify your account using the secure link below.\n"
	spf := p.pick([]string{"pass", "pass", "softfail"})
	return benchEmail{
		name:     fmt.Sprintf("dga-%d", n),
		category: "DGA",
		eml:      buildEML("updates@retail-news.com", "user@mailhook.test", "Account Verification Required", spf, spf, spf, body, []string{"https://" + d1 + beacon, "https://" + d2 + beacon}),
	}
}

func (p *prng) genClean(n int) benchEmail {
	body := p.pick(cleanBodies) + "\n\nVisit us at https://github.com/ or https://google.com/ for more."
	return benchEmail{
		name:     fmt.Sprintf("clean-%d", n),
		category: "CLEAN",
		eml:      buildEML(p.pick(cleanSenders), "user@mailhook.test", p.pick(cleanSubjects), "pass", "pass", "pass", body, nil),
	}
}

func (p *prng) genFP(n int) benchEmail {
	body := "Your password reset link will expire in 10 minutes. Click here to reset your password.\n"
	return benchEmail{
		name:     fmt.Sprintf("fp-%d", n),
		category: "CLEAN",
		eml:      buildEML("noreply@accounts.google.com", "user@mailhook.test", "Action Required: Verify Your Email", "pass", "pass", "pass", body, []string{"https://accounts.google.com/reset?token=abc123"}),
	}
}

func generateEmails(n int, seed uint64) []benchEmail {
	p := newPRNG(seed)
	emails := make([]benchEmail, 0, n)
	bec, phish, dga, clean, fp := 0, 0, 0, 0, 0
	for i := range n {
		switch {
		case i%20 < 5:
			clean++
			emails = append(emails, p.genClean(clean))
		case i%20 < 10:
			bec++
			emails = append(emails, p.genBEC(bec))
		case i%20 < 14:
			phish++
			emails = append(emails, p.genPhish(phish))
		case i%20 < 17:
			dga++
			emails = append(emails, p.genDGA(dga))
		default:
			fp++
			emails = append(emails, p.genFP(fp))
		}
	}
	return emails
}

// ─── HTTP scan client ─────────────────────────────────────────────────────────

type scanResult struct {
	Verdict    string      `json:"verdict"`
	Decision   string      `json:"decision"`
	Reason     string      `json:"reason"`
	Confidence float64     `json:"confidence"`
	ElapsedMs  int64       `json:"elapsed_ms"`
	Scanners   interface{} `json:"scanners"`
}

func doScan(client *http.Client, baseURL string, eml []byte) (scanResult, time.Duration, error) {
	t0 := time.Now()
	resp, err := client.Post(baseURL+"/api/scan", "message/rfc822", bytes.NewReader(eml))
	wallTime := time.Since(t0)
	if err != nil {
		return scanResult{}, wallTime, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return scanResult{}, wallTime, fmt.Errorf("HTTP %d: %s", resp.StatusCode, body)
	}
	var r scanResult
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return scanResult{}, wallTime, err
	}
	return r, wallTime, nil
}

func waitHealthy(baseURL string, timeout time.Duration) error {
	client := &http.Client{Timeout: 5 * time.Second}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := client.Get(baseURL + "/health")
		if err == nil && resp.StatusCode == http.StatusOK {
			resp.Body.Close()
			return nil
		}
		if resp != nil {
			resp.Body.Close()
		}
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("timed out waiting for %s to become healthy", baseURL)
}

// ─── Result types ─────────────────────────────────────────────────────────────

type runRow struct {
	email    benchEmail
	stdVerdict string
	aiVerdict  string
	stdMs    int64
	aiMs     int64
	err      string
}

type jsonOut struct {
	Scenario string `json:"scenario"`
	Category string `json:"category"`
	Standard string `json:"standard"`
	AI       string `json:"ai"`
	StdMs    int64  `json:"std_ms"`
	AIMs     int64  `json:"ai_ms"`
	AIOnly   bool   `json:"ai_only_detection"`
	Changed  bool   `json:"verdict_changed"`
}

// ─── ANSI helpers ─────────────────────────────────────────────────────────────

const (
	ansiReset  = "\033[0m"
	ansiRed    = "\033[31m"
	ansiGreen  = "\033[32m"
	ansiYellow = "\033[33m"
	ansiCyan   = "\033[36m"
	ansiBold   = "\033[1m"
)

func coloredV(v string) string {
	switch {
	case strings.HasPrefix(v, "delete"):
		return ansiRed + v + ansiReset
	case strings.HasPrefix(v, "quarantine"):
		return ansiYellow + v + ansiReset
	case strings.HasPrefix(v, "flag"):
		return ansiCyan + v + ansiReset
	default:
		return ansiGreen + v + ansiReset
	}
}

func p50p95p99(ms []int64) (int64, int64, int64) {
	if len(ms) == 0 {
		return 0, 0, 0
	}
	sorted := make([]int64, len(ms))
	copy(sorted, ms)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	idx := func(pct float64) int64 {
		i := int(float64(len(sorted)-1) * pct)
		return sorted[i]
	}
	return idx(0.50), idx(0.95), idx(0.99)
}

// validateBenchURL ensures the target URL is a well-formed http/https address.
// Prevents the taint flow from CLI flag → HTTP request being flagged as SSRF.
func validateBenchURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("scheme must be http or https, got %q", u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("host must not be empty")
	}
	return nil
}

// ─── Main ─────────────────────────────────────────────────────────────────────

func main() {
	stdURL := flag.String("std", "http://localhost:8080", "Standard MailHook base URL")
	aiURL := flag.String("ai", "http://localhost:8081", "AI MailHook base URL")
	n := flag.Int("n", 50, "Number of scenarios to generate")
	seed := flag.Uint64("seed", 0, "PRNG seed (0 = random)")
	format := flag.String("format", "table", "Output format: table | json")
	noWait := flag.Bool("no-wait", false, "Skip health-check wait")
	timeout := flag.Duration("timeout", 60*time.Second, "Per-scan HTTP timeout")
	flag.Parse()

	if err := validateBenchURL(*stdURL); err != nil {
		fmt.Fprintf(os.Stderr, "invalid -std URL: %v\n", err)
		os.Exit(1)
	}
	if err := validateBenchURL(*aiURL); err != nil {
		fmt.Fprintf(os.Stderr, "invalid -ai URL: %v\n", err)
		os.Exit(1)
	}

	if !*noWait {
		fmt.Printf("Waiting for standard build  %s ...", *stdURL)
		if err := waitHealthy(*stdURL, 120*time.Second); err != nil {
			fmt.Println(" FAIL")
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(" OK")

		fmt.Printf("Waiting for AI build        %s ...", *aiURL)
		if err := waitHealthy(*aiURL, 120*time.Second); err != nil {
			fmt.Println(" FAIL")
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(" OK")
	}

	client := &http.Client{Timeout: *timeout}
	emails := generateEmails(*n, *seed)

	fmt.Printf("Running %d scenarios against both builds...\n\n", len(emails))

	rows := make([]runRow, len(emails))
	for i, em := range emails {
		var r runRow
		r.email = em

		stdRes, stdWall, err := doScan(client, *stdURL, em.eml)
		if err != nil {
			r.err = "std: " + err.Error()
			r.stdVerdict = "error/ERROR"
		} else {
			r.stdVerdict = stdRes.Decision + "/" + stdRes.Verdict
			r.stdMs = stdWall.Milliseconds()
		}

		aiRes, aiWall, err := doScan(client, *aiURL, em.eml)
		if err != nil {
			if r.err != "" {
				r.err += "; "
			}
			r.err += "ai: " + err.Error()
			r.aiVerdict = "error/ERROR"
		} else {
			r.aiVerdict = aiRes.Decision + "/" + aiRes.Verdict
			r.aiMs = aiWall.Milliseconds()
		}
		rows[i] = r
	}

	switch *format {
	case "json":
		emitJSON(rows)
	default:
		emitTable(rows)
	}
}

func emitTable(rows []runRow) {
	fmt.Printf("%s╔══ MailHook Live Bench — Standard vs AI Build ══╗%s\n\n", ansiBold, ansiReset)

	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "%s%-20s %-10s %-22s %-22s %-8s %-8s %s%s\n",
		ansiBold, "SCENARIO", "CATEGORY", "STANDARD", "AI BUILD", "STD ms", "AI ms", "DELTA", ansiReset)
	fmt.Fprintln(tw, strings.Repeat("─", 100))

	blocked := func(v string) bool { return strings.HasPrefix(v, "quarantine") || strings.HasPrefix(v, "delete") }
	passed := func(v string) bool { return strings.HasPrefix(v, "pass") || strings.HasPrefix(v, "flag") }

	aiOnly, aiBlocked, stdBlocked := 0, 0, 0
	var stdMs, aiMs []int64

	for _, r := range rows {
		delta := "—"
		if r.stdVerdict != r.aiVerdict {
			if blocked(r.aiVerdict) && passed(r.stdVerdict) {
				delta = ansiGreen + "✓ AI catches" + ansiReset
			} else {
				delta = ansiCyan + "Δ changed" + ansiReset
			}
		}
		if r.err != "" {
			delta = ansiRed + "ERR" + ansiReset
		}
		fmt.Fprintf(tw, "%-20s %-10s %-22s %-22s %-8d %-8d %s\n",
			r.email.name, r.email.category,
			coloredV(r.stdVerdict), coloredV(r.aiVerdict),
			r.stdMs, r.aiMs, delta)

		if blocked(r.stdVerdict) {
			stdBlocked++
		}
		if blocked(r.aiVerdict) {
			aiBlocked++
			if passed(r.stdVerdict) {
				aiOnly++
			}
		}
		if r.stdMs > 0 {
			stdMs = append(stdMs, r.stdMs)
		}
		if r.aiMs > 0 {
			aiMs = append(aiMs, r.aiMs)
		}
	}
	tw.Flush()

	sp50, sp95, sp99 := p50p95p99(stdMs)
	ap50, ap95, ap99 := p50p95p99(aiMs)
	overhead := ap50 - sp50

	fmt.Printf("\n%s── Summary ──────────────────────────────────────────────%s\n", ansiBold, ansiReset)
	fmt.Printf("  Total scenarios:        %d\n", len(rows))
	fmt.Printf("  Standard detections:    %d  (quarantine or delete)\n", stdBlocked)
	fmt.Printf("  AI build detections:    %d  (quarantine or delete)\n", aiBlocked)
	fmt.Printf("  AI-only improvements:   %s%d%s  (threats standard missed)\n", ansiGreen, aiOnly, ansiReset)
	fmt.Printf("\n%s── Latency ──────────────────────────────────────────────%s\n", ansiBold, ansiReset)
	fmt.Printf("  Standard  p50=%dms  p95=%dms  p99=%dms\n", sp50, sp95, sp99)
	fmt.Printf("  AI build  p50=%dms  p95=%dms  p99=%dms\n", ap50, ap95, ap99)
	if overhead >= 0 {
		fmt.Printf("  AI overhead (p50):  +%dms\n", overhead)
	}

	if aiOnly > 0 {
		fmt.Printf("\n%s── Threats the standard build misses ────────────────────%s\n", ansiBold, ansiReset)
		for _, r := range rows {
			if blocked(r.aiVerdict) && passed(r.stdVerdict) {
				fmt.Printf("  • %s%s%s  [%s]  std=%s → ai=%s\n",
					ansiBold, r.email.name, ansiReset, r.email.category,
					r.stdVerdict, r.aiVerdict)
			}
		}
	}
	fmt.Println()
}

func emitJSON(rows []runRow) {
	blocked := func(v string) bool { return strings.HasPrefix(v, "quarantine") || strings.HasPrefix(v, "delete") }
	passed := func(v string) bool { return strings.HasPrefix(v, "pass") || strings.HasPrefix(v, "flag") }

	var out []jsonOut
	for _, r := range rows {
		out = append(out, jsonOut{
			Scenario: r.email.name,
			Category: r.email.category,
			Standard: r.stdVerdict,
			AI:       r.aiVerdict,
			StdMs:    r.stdMs,
			AIMs:     r.aiMs,
			AIOnly:   blocked(r.aiVerdict) && passed(r.stdVerdict),
			Changed:  r.stdVerdict != r.aiVerdict,
		})
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(out) //nolint:errcheck
}
