package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/izm1chael/mailhook/config"
	"github.com/izm1chael/mailhook/db"
	"github.com/izm1chael/mailhook/pipeline"
	"github.com/izm1chael/mailhook/util"
)

// Notifier sends push notifications via ntfy when a threat is detected.
// All sends are fire-and-forget — failures are logged but never block the pipeline.
type Notifier struct {
	cfg    *config.Config
	client *http.Client
	log    *slog.Logger

	// Debounce: track last engine-down notification to avoid spam
	lastEngineDown  map[string]time.Time
	engineDownMu    sync.Mutex

	webhookURL      string
	webhookVerdicts []string
	webhookMu       sync.RWMutex
}

// New creates a Notifier. If cfg.NtfyURL is empty, Send is a no-op.
func New(cfg *config.Config, log *slog.Logger) *Notifier {
	return &Notifier{
		cfg:            cfg,
		client:         newSSRFSafeClient(10 * time.Second),
		log:            log,
		lastEngineDown: make(map[string]time.Time),
	}
}

// newSSRFSafeClient returns an HTTP client whose DialContext resolves once,
// validates that the resolved IP is public, and pins the connection to that IP.
// This closes the TOCTOU window between a pre-flight DNS check and the actual
// HTTP request — a DNS rebinding attacker cannot change the IP after the check.
func newSSRFSafeClient(timeout time.Duration) *http.Client {
	dialer := &net.Dialer{Timeout: timeout}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, fmt.Errorf("ssrf: invalid addr %q: %w", addr, err)
			}
			ips, err := net.DefaultResolver.LookupHost(ctx, host)
			if err != nil || len(ips) == 0 {
				return nil, fmt.Errorf("ssrf: cannot resolve %q: %w", host, err)
			}
			ip := net.ParseIP(ips[0])
			if ip == nil || !util.IsPublicIP(ip) {
				return nil, fmt.Errorf("ssrf: %q resolves to non-public address %s", host, ips[0])
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0], port))
		},
	}
	return &http.Client{Timeout: timeout, Transport: transport}
}

// SetWebhook configures the outbound webhook URL and the verdicts that trigger it.
func (n *Notifier) SetWebhook(url, verdicts string) {
	n.webhookMu.Lock()
	defer n.webhookMu.Unlock()
	n.webhookURL = url
	if verdicts == "" {
		n.webhookVerdicts = []string{"MALWARE", "PHISH"}
	} else {
		n.webhookVerdicts = strings.Split(verdicts, ",")
	}
}

// redact returns masked From and Subject when RedactWebhookPII is enabled.
// "alice@example.com" → "***@example.com"; Subject → "[redacted]".
func (n *Notifier) redact(from, subject string) (string, string) {
	if !n.cfg.RedactWebhookPII {
		return from, subject
	}
	if idx := strings.Index(from, "@"); idx >= 0 {
		from = "***" + from[idx:]
	} else if from != "" {
		from = "***"
	}
	return from, "[redacted]"
}

func (n *Notifier) sendWebhook(ctx context.Context, email *pipeline.Email, vd pipeline.VerdictDecision) {
	n.webhookMu.RLock()
	url := n.webhookURL
	verdicts := n.webhookVerdicts
	n.webhookMu.RUnlock()
	if url == "" {
		return
	}
	match := false
	for _, v := range verdicts {
		if strings.EqualFold(strings.TrimSpace(v), vd.Verdict) {
			match = true
			break
		}
	}
	if !match {
		return
	}
	// SSRF guard is enforced by the pinning DialContext in newSSRFSafeClient:
	// DNS resolves once, the resolved IP is validated as public, and the connection
	// is pinned to that IP — eliminating the TOCTOU window (F-022).
	go func() { // #nosec G118 -- fire-and-forget notification must outlive the request context
		type payload struct {
			Verdict    string    `json:"verdict"`
			From       string    `json:"from"`
			Subject    string    `json:"subject"`
			Account    string    `json:"account"`
			Confidence float64   `json:"confidence"`
			Reason     string    `json:"reason"`
			ReceivedAt time.Time `json:"received_at"`
		}
		from, subject := n.redact(email.From, email.Subject)
		p := payload{
			Verdict:    vd.Verdict,
			From:       from,
			Subject:    subject,
			Account:    email.AccountName,
			Confidence: vd.Confidence,
			Reason:     vd.Reason,
			ReceivedAt: time.Now(),
		}
		data, err := marshalJSON(p)
		if err != nil {
			return
		}
		ctx2, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx2, http.MethodPost, url, bytes.NewReader(data))
		if err != nil {
			n.log.Warn("webhook: bad URL", "err", err)
			return
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := n.client.Do(req)
		if err != nil {
			n.log.Warn("webhook: send failed", "err", err)
			return
		}
		resp.Body.Close() //nolint:errcheck
		if resp.StatusCode >= 400 {
			n.log.Warn("webhook: server error", "status", resp.StatusCode)
		}
	}()
}

// Send dispatches a push notification for the given email verdict.
// Returns immediately — the HTTP request runs in a goroutine.
func (n *Notifier) Send(ctx context.Context, email *pipeline.Email, vd pipeline.VerdictDecision) {
	if n.cfg.NtfyURL != "" {
		from, subject := n.redact(email.From, email.Subject)
		title, priority, tags := notificationParams(vd)
		body := fmt.Sprintf("Account: %s\nFrom: %s\nSubject: %s\n%s",
			email.AccountName, from, subject, vd.Reason)
		go n.post(context.Background(), title, priority, tags, body) // #nosec G118 -- fire-and-forget notification must outlive the request context
	}
	n.sendWebhook(ctx, email, vd)
}

func marshalJSON(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}

// SendTest sends a test notification to verify ntfy connectivity.
func (n *Notifier) SendTest(ctx context.Context) error {
	if n.cfg.NtfyURL == "" {
		return fmt.Errorf("ntfy URL not configured")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		n.cfg.NtfyURL, strings.NewReader("MailHook test notification — if you see this, notifications are working."))
	if err != nil {
		return err
	}
	req.Header.Set("Title", "MailHook Test")
	req.Header.Set("Priority", "default")
	req.Header.Set("Tags", "mailhook,test")
	if n.cfg.NtfyToken != "" {
		req.Header.Set("Authorization", "Bearer "+n.cfg.NtfyToken)
	}
	resp, err := n.client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("ntfy returned %d", resp.StatusCode)
	}
	return nil
}

// NotifyEngineDown sends a one-per-hour alert when a scanner becomes unreachable.
func (n *Notifier) NotifyEngineDown(component string) {
	if n.cfg.NtfyURL == "" {
		return
	}
	// Debounce: don't send more than once per hour per component
	n.engineDownMu.Lock()
	if last, ok := n.lastEngineDown[component]; ok && time.Since(last) < time.Hour {
		n.engineDownMu.Unlock()
		return
	}
	n.lastEngineDown[component] = time.Now()
	n.engineDownMu.Unlock()
	go n.post(context.Background(),
		"MailHook Scanner Unhealthy",
		"default",
		"warning,mailhook",
		fmt.Sprintf("%s is unreachable — scanning in degraded mode", component),
	)
}

func (n *Notifier) post(ctx context.Context, title, priority, tags, body string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		n.cfg.NtfyURL, strings.NewReader(body))
	if err != nil {
		n.log.Warn("ntfy request build failed", "err", err)
		return
	}
	req.Header.Set("Title", title)
	req.Header.Set("Priority", priority)
	req.Header.Set("Tags", tags)
	if n.cfg.NtfyToken != "" {
		req.Header.Set("Authorization", "Bearer "+n.cfg.NtfyToken)
	}

	resp, err := n.client.Do(req)
	if err != nil {
		n.log.Warn("ntfy send failed", "err", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		n.log.Warn("ntfy returned error", "status", resp.StatusCode)
	}
}

// NotifyRetroClawback sends a push notification when a previously-clean email is
// retrospectively quarantined after a threat feed update.
func (n *Notifier) NotifyRetroClawback(ctx context.Context, scan *db.Scan, hits []db.URLHit) {
	if n.cfg.NtfyURL == "" {
		return
	}
	feedNames := make([]string, 0, len(hits))
	for _, h := range hits {
		feedNames = append(feedNames, h.Feed)
	}
	from, subject := n.redact(scan.From, scan.Subject)
	body := fmt.Sprintf("From: %s\nSubject: %s\nURL: %s\nFeed: %s",
		from, subject, hits[0].URL, strings.Join(feedNames, ", "))
	n.post(ctx,
		"⏪ Retro Clawback — Threat Detected",
		"high",
		"warning,email,retro",
		body,
	)
}

func notificationParams(vd pipeline.VerdictDecision) (title, priority, tags string) {
	switch vd.Verdict {
	case "MALWARE":
		return "MailHook: Malware Blocked", "urgent", "warning,email,malware"
	case "PHISH":
		return "MailHook: Phishing Blocked", "high", "warning,email,phishing"
	case "SPAM":
		return "MailHook: Spam Quarantined", "default", "email,spam"
	case "SUSPICIOUS":
		return "MailHook: Suspicious Email Flagged", "low", "email,suspicious"
	default:
		return "MailHook: Email Processed", "min", "email"
	}
}
