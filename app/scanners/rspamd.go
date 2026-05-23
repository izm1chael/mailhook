package scanners

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/izm1chael/mailhook/db"
	"github.com/izm1chael/mailhook/pipeline"
)

// Rspamd scans emails via the Rspamd HTTP API and provides Bayes learn endpoints.
type Rspamd struct {
	mu      sync.RWMutex
	enabled bool
	url     string
	client  *http.Client
	log     *slog.Logger
}

type rspamdResponse struct {
	Score   float64                       `json:"score"`
	Action  string                        `json:"action"`
	Symbols map[string]rspamdSymbolDetail `json:"symbols"`
}

type rspamdSymbolDetail struct {
	Score       float64 `json:"score"`
	Description string  `json:"description"`
}

// NewRspamd creates a Rspamd scanner pointing at the given URL (e.g. "http://rspamd:11333").
func NewRspamd(url string, log *slog.Logger) *Rspamd {
	return &Rspamd{
		enabled: true,
		url:     url,
		client:  &http.Client{Timeout: 30 * time.Second},
		log:     log,
	}
}

// SetEnabled enables or disables the scanner at runtime.
func (r *Rspamd) SetEnabled(v bool) { r.mu.Lock(); r.enabled = v; r.mu.Unlock() }

// SetURL changes the Rspamd endpoint URL at runtime.
func (r *Rspamd) SetURL(url string) { r.mu.Lock(); r.url = url; r.mu.Unlock() }

// IsEnabled reports whether the scanner is currently enabled.
func (r *Rspamd) IsEnabled() bool { r.mu.RLock(); defer r.mu.RUnlock(); return r.enabled }

func (r *Rspamd) Name() string { return "rspamd" }

// Scan POSTs the raw email to /checkv2 and maps the action/score to a verdict.
func (r *Rspamd) Scan(ctx context.Context, email *pipeline.Email) pipeline.ScanResult {
	r.mu.RLock()
	enabled := r.enabled
	r.mu.RUnlock()
	if !enabled {
		return pipeline.ScanResult{Scanner: r.Name(), Verdict: "skip", Detail: "disabled"}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		r.url+"/checkv2", bytes.NewReader(email.Raw))
	if err != nil {
		return pipeline.ScanResult{Scanner: r.Name(), Verdict: "error", Detail: err.Error()}
	}
	req.Header.Set("Content-Type", "message/rfc822")
	req.Header.Set("Pass", "all") // return all symbols regardless of action

	resp, err := r.client.Do(req)
	if err != nil {
		r.log.Warn("rspamd unavailable", "err", err)
		// "error" triggers fail-closed quarantine in verdict.go; "skip" is reserved for disabled-only.
		return pipeline.ScanResult{Scanner: r.Name(), Verdict: "error", Detail: "rspamd unavailable: " + err.Error()}
	}
	defer resp.Body.Close()

	var rr rspamdResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1*1024*1024)).Decode(&rr); err != nil {
		return pipeline.ScanResult{Scanner: r.Name(), Verdict: "error", Detail: fmt.Sprintf("decode: %v", err)}
	}

	var syms []db.RspamdSymbol
	for name, s := range rr.Symbols {
		syms = append(syms, db.RspamdSymbol{Name: name, Score: s.Score, Description: s.Description})
	}
	symData, _ := json.Marshal(syms)

	verdict := actionToVerdict(rr.Action)
	return pipeline.ScanResult{
		Scanner: r.Name(),
		Verdict: verdict,
		Score:   rr.Score,
		Detail:  rr.Action,
		Matches: symData,
	}
}

// LearnSpam submits raw EML to Rspamd's Bayes spam learner.
func (r *Rspamd) LearnSpam(ctx context.Context, raw []byte) error {
	return r.learn(ctx, "/learnspam", raw)
}

// LearnHam submits raw EML to Rspamd's Bayes ham learner.
func (r *Rspamd) LearnHam(ctx context.Context, raw []byte) error {
	return r.learn(ctx, "/learnham", raw)
}

func (r *Rspamd) learn(ctx context.Context, endpoint string, raw []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		r.url+endpoint, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "message/rfc822")

	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("rspamd learn request: %w", err)
	}
	// Drain body before Close so the underlying TCP connection can be reused.
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096)) //nolint:errcheck
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("rspamd learn returned HTTP %d", resp.StatusCode)
	}
	return nil
}

// Ping checks whether the Rspamd server is reachable.
func (r *Rspamd) Ping(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.url+"/ping", nil)
	if err != nil {
		return err
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return err
	}
	// Drain body before Close so the underlying TCP connection can be reused.
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096)) //nolint:errcheck
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("rspamd ping returned HTTP %d", resp.StatusCode)
	}
	return nil
}

func actionToVerdict(action string) string {
	switch action {
	case "reject":
		return "malicious"
	case "add header", "rewrite subject", "greylist":
		return "suspicious"
	default:
		return "clean"
	}
}
