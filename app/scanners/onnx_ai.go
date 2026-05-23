//go:build ai

package scanners

import (
	"bytes"
	"context"
	"embed"
	"fmt"
	"log/slog"
	"math"
	"os"
	"strings"
	"sync"

	tokenizerpkg "github.com/sugarme/tokenizer"
	"github.com/sugarme/tokenizer/pretrained"
	ort "github.com/yalue/onnxruntime_go"

	"github.com/izm1chael/mailhook/config"
	"github.com/izm1chael/mailhook/pipeline"
)

// models/ is the embedded model directory. At build time it must contain at
// least tranco-top10k.txt (populated by 'make models-dl'). The ONNX model
// files (model.onnx, tokenizer.json) are large and not committed to git;
// run 'make models-bert' and provide a DGA model before 'make build-ai'.
//
//go:embed models
var embeddedModels embed.FS

const (
	bertMaxTokens        = 512
	dgaMaxDomainLen      = 75 // matches MAXLEN in Reynier/dga-cnn model.py
	defaultBERTThreshold = 0.92
	defaultDGAThreshold  = 0.80
)

var onnxInitOnce sync.Once

// ONNXScanner runs DistilBERT (phishing URL classification) and a DGA CNN (domain analysis).
// Models are embedded in the binary at build time via //go:embed — no separate
// model directory is required at runtime. Each model is independently optional;
// a missing model is logged and that sub-scanner is skipped.
type ONNXScanner struct {
	mu sync.RWMutex

	bertSession   *ort.DynamicAdvancedSession
	bertTokenizer *tokenizerpkg.Tokenizer
	bertThreshold float32

	dgaSession   *ort.DynamicAdvancedSession
	dgaThreshold float32

	tranco  map[string]struct{}
	enabled bool

	log *slog.Logger
}

// NewONNXScanner initialises ONNX Runtime and loads embedded models.
// Model load failures are non-fatal — each sub-scanner logs a warning and
// returns skip results. ONNX Runtime init failure is fatal.
func NewONNXScanner(cfg *config.Config, log *slog.Logger) (*ONNXScanner, error) {
	s := &ONNXScanner{
		log:           log,
		bertThreshold: float32(cfg.ONNXBERTThreshold),
		dgaThreshold:  float32(cfg.ONNXDGAThreshold),
		tranco:        make(map[string]struct{}),
		enabled:       true,
	}
	if s.bertThreshold == 0 {
		s.bertThreshold = defaultBERTThreshold
	}
	if s.dgaThreshold == 0 {
		s.dgaThreshold = defaultDGAThreshold
	}

	// Allow the ONNX RT shared library path to be overridden via env.
	if rtPath := os.Getenv("ONNXRUNTIME_LIB_PATH"); rtPath != "" {
		ort.SetSharedLibraryPath(rtPath)
	}

	var initErr error
	onnxInitOnce.Do(func() {
		initErr = ort.InitializeEnvironment()
	})
	if initErr != nil {
		return nil, fmt.Errorf("onnx runtime init: %w", initErr)
	}

	// Tranco greylist — embedded; fall back to cfg.ONNXModelsDir if absent.
	if err := s.loadTrancoEmbedded(); err != nil {
		if cfg.ONNXModelsDir != "" {
			if err2 := s.loadTrancoFile(cfg.ONNXModelsDir + "/tranco-top10k.txt"); err2 != nil {
				log.Warn("onnx: tranco load failed — DGA will run on all domains", "err", err2)
			}
		} else {
			log.Warn("onnx: tranco not embedded — DGA will run on all domains", "err", err)
		}
	}

	// DistilBERT — embedded first, disk fallback.
	if err := s.loadBERTEmbedded(); err != nil {
		if cfg.ONNXModelsDir != "" {
			if err2 := s.loadBERTDir(cfg.ONNXModelsDir + "/distilbert-phishing"); err2 != nil {
				log.Warn("onnx: distilbert load failed — BEC detection disabled", "err", err2)
			}
		} else {
			log.Warn("onnx: distilbert not embedded — BEC detection disabled", "err", err)
		}
	}

	// DGA CNN — embedded first, disk fallback.
	if err := s.loadDGAEmbedded(); err != nil {
		if cfg.ONNXModelsDir != "" {
			if err2 := s.loadDGAFile(cfg.ONNXModelsDir + "/dga-cnn/model.onnx"); err2 != nil {
				log.Warn("onnx: dga-cnn load failed — DGA detection disabled", "err", err2)
			}
		} else {
			log.Warn("onnx: dga-cnn not embedded — DGA detection disabled", "err", err)
		}
	}

	return s, nil
}

func (o *ONNXScanner) Name() string { return "onnx" }

func (o *ONNXScanner) SetEnabled(v bool) {
	o.mu.Lock()
	o.enabled = v
	o.mu.Unlock()
}

func (o *ONNXScanner) IsEnabled() bool {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.enabled
}

// Close releases ONNX sessions. Call on shutdown.
func (o *ONNXScanner) Close() {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.bertSession != nil {
		o.bertSession.Destroy() //nolint:errcheck
		o.bertSession = nil
	}
	if o.dgaSession != nil {
		o.dgaSession.Destroy() //nolint:errcheck
		o.dgaSession = nil
	}
}

// Scan runs both models and returns the highest-priority result.
func (o *ONNXScanner) Scan(ctx context.Context, email *pipeline.Email) pipeline.ScanResult {
	o.mu.RLock()
	enabled := o.enabled
	bertOK := o.bertSession != nil && o.bertTokenizer != nil
	dgaOK := o.dgaSession != nil
	o.mu.RUnlock()

	if !enabled {
		return pipeline.ScanResult{Scanner: o.Name(), Verdict: "skip", Detail: "disabled"}
	}
	if !bertOK && !dgaOK {
		return pipeline.ScanResult{Scanner: o.Name(), Verdict: "skip", Detail: "no models loaded"}
	}

	var bertScore, dgaScore float32
	var bertDetail, dgaDetail string

	// ── DistilBERT: phishing URL detection ────────────────────────────────────
	// cybersectony/phishing-email-detection-distilbert_v2.4.1 is a 4-class
	// URL classifier (not an email-body prose model):
	//   label 0 = legitimate_email, 1 = phishing_url,
	//   label 2 = legitimate_url,   3 = phishing_url_alt
	// We run it per-URL and take the max phish score across all URLs.
	if bertOK && len(email.URLs) > 0 {
		for _, rawURL := range email.URLs {
			if domain := extractDomain(rawURL); o.isTrancoGreylisted(domain) {
				continue
			}
			score, err := o.runBERT(rawURL)
			if err != nil {
				o.log.Debug("onnx bert inference error", "url", rawURL, "err", err)
				continue
			}
			o.log.Debug("onnx bert score", "url", rawURL, "score", score, "threshold", o.bertThreshold)
			if score > bertScore {
				bertScore = score
				bertDetail = fmt.Sprintf("bert_phish=%.3f url=%s", score, rawURL)
			}
		}
	}

	// ── DGA CNN: algorithmically generated domains ────────────────────────────
	if dgaOK && len(email.URLs) > 0 {
		for _, domain := range extractDomains(email.URLs) {
			if o.isTrancoGreylisted(domain) {
				continue
			}
			score, err := o.runDGA(domain)
			if err != nil {
				o.log.Debug("onnx dga inference error", "domain", domain, "err", err)
				continue
			}
			if score > dgaScore {
				dgaScore = score
				dgaDetail = fmt.Sprintf("dga_score=%.3f domain=%s", score, domain)
			}
		}
	}

	// ── Verdict ───────────────────────────────────────────────────────────────
	if bertScore > o.bertThreshold {
		return pipeline.ScanResult{
			Scanner: o.Name(),
			Verdict: "malicious",
			Score:   float64(bertScore),
			Detail:  "DistilBERT phishing URL: " + bertDetail,
		}
	}
	if dgaScore > o.dgaThreshold {
		return pipeline.ScanResult{
			Scanner: o.Name(),
			Verdict: "suspicious",
			Score:   float64(dgaScore),
			Detail:  "DGA domain detected: " + dgaDetail,
		}
	}

	parts := []string{}
	if bertDetail != "" {
		parts = append(parts, bertDetail)
	}
	if dgaDetail != "" {
		parts = append(parts, dgaDetail)
	}
	detail := "clean"
	if len(parts) > 0 {
		detail = strings.Join(parts, " ")
	}
	return pipeline.ScanResult{
		Scanner: o.Name(),
		Verdict: "clean",
		Score:   float64(max32(bertScore, dgaScore)),
		Detail:  detail,
	}
}

// ── DistilBERT ────────────────────────────────────────────────────────────────

func (o *ONNXScanner) loadBERTEmbedded() error {
	modelData, err := embeddedModels.ReadFile("models/distilbert-phishing/model.onnx")
	if err != nil {
		return err
	}
	tokData, err := embeddedModels.ReadFile("models/distilbert-phishing/tokenizer.json")
	if err != nil {
		return err
	}
	return o.initBERT(modelData, tokData)
}

func (o *ONNXScanner) loadBERTDir(dir string) error {
	modelData, err := os.ReadFile(dir + "/model.onnx") // #nosec G304 -- dir is the operator-configured model directory, not request input
	if err != nil {
		return err
	}
	tokData, err := os.ReadFile(dir + "/tokenizer.json") // #nosec G304 -- dir is the operator-configured model directory, not request input
	if err != nil {
		return err
	}
	return o.initBERT(modelData, tokData)
}

func (o *ONNXScanner) initBERT(modelData, tokData []byte) error {
	// Verify tensor names against your export with:
	//   python3 -c "import onnx; m=onnx.load('model.onnx'); print([i.name for i in m.graph.input])"
	inputNames := []string{"input_ids", "attention_mask"}
	outputNames := []string{"logits"}

	session, err := ort.NewDynamicAdvancedSessionWithONNXData(modelData, inputNames, outputNames, nil)
	if err != nil {
		return fmt.Errorf("bert session: %w", err)
	}

	tk, err := pretrained.FromReader(bytes.NewReader(tokData))
	if err != nil {
		session.Destroy() //nolint:errcheck
		return fmt.Errorf("tokenizer: %w", err)
	}

	o.mu.Lock()
	o.bertSession = session
	o.bertTokenizer = tk
	o.mu.Unlock()
	return nil
}

func (o *ONNXScanner) runBERT(text string) (float32, error) {
	o.mu.RLock()
	session := o.bertSession
	tk := o.bertTokenizer
	o.mu.RUnlock()

	if len(text) > 4000 {
		text = text[:4000]
	}

	encoding, err := tk.EncodeSingle(text, true)
	if err != nil {
		return 0, fmt.Errorf("tokenize: %w", err)
	}

	ids := padOrTruncateInt(encoding.Ids, bertMaxTokens, 0)
	mask := padOrTruncateInt(encoding.AttentionMask, bertMaxTokens, 0)

	inputIDs := make([]int64, bertMaxTokens)
	attMask := make([]int64, bertMaxTokens)
	for i := range ids {
		inputIDs[i] = int64(ids[i])
		attMask[i] = int64(mask[i])
	}

	shape := ort.NewShape(1, int64(bertMaxTokens))

	idsT, err := ort.NewTensor(shape, inputIDs)
	if err != nil {
		return 0, err
	}
	defer idsT.Destroy() //nolint:errcheck

	maskT, err := ort.NewTensor(shape, attMask)
	if err != nil {
		return 0, err
	}
	defer maskT.Destroy() //nolint:errcheck

	// The deployed model (cybersectony distilbert v2.4.1) has 4 output classes.
	// Use shape (1,4); softmaxPhish handles arbitrary N by summing phish indices.
	outShape := ort.NewShape(1, 4)
	outT, err := ort.NewEmptyTensor[float32](outShape)
	if err != nil {
		return 0, err
	}
	defer outT.Destroy() //nolint:errcheck

	// DynamicAdvancedSession.Run takes []ort.Value; *ort.Tensor[T] implements Value.
	if err := session.Run(
		[]ort.Value{idsT, maskT},
		[]ort.Value{outT},
	); err != nil {
		return 0, err
	}

	logits := outT.GetData()
	if len(logits) < 2 {
		return 0, fmt.Errorf("unexpected bert output shape: %d", len(logits))
	}
	if len(logits) == 2 {
		return softmax2(logits[0], logits[1]), nil
	}
	// 4-class model: labels 1 (phishing_url) + 3 (phishing_url_alt) are phish.
	return softmaxPhish(logits, 1, 3), nil
}

// ── DGA CNN ───────────────────────────────────────────────────────────────────

func (o *ONNXScanner) loadDGAEmbedded() error {
	data, err := embeddedModels.ReadFile("models/dga-cnn/model.onnx")
	if err != nil {
		return err
	}
	return o.initDGA(data)
}

func (o *ONNXScanner) loadDGAFile(path string) error {
	data, err := os.ReadFile(path) // #nosec G304 -- path is an operator-configured model/data file, not request input
	if err != nil {
		return err
	}
	return o.initDGA(data)
}

func (o *ONNXScanner) initDGA(data []byte) error {
	session, err := ort.NewDynamicAdvancedSessionWithONNXData(
		data,
		[]string{"domain_chars"},
		[]string{"logits"},
		nil,
	)
	if err != nil {
		return fmt.Errorf("dga session: %w", err)
	}
	o.mu.Lock()
	o.dgaSession = session
	o.mu.Unlock()
	return nil
}

func (o *ONNXScanner) runDGA(domain string) (float32, error) {
	o.mu.RLock()
	session := o.dgaSession
	o.mu.RUnlock()

	encoded := encodeDomainChars(domain, dgaMaxDomainLen)
	shape := ort.NewShape(1, int64(dgaMaxDomainLen))

	inputT, err := ort.NewTensor(shape, encoded)
	if err != nil {
		return 0, err
	}
	defer inputT.Destroy() //nolint:errcheck

	outShape := ort.NewShape(1, 2)
	outT, err := ort.NewEmptyTensor[float32](outShape)
	if err != nil {
		return 0, err
	}
	defer outT.Destroy() //nolint:errcheck

	if err := session.Run(
		[]ort.Value{inputT},
		[]ort.Value{outT},
	); err != nil {
		return 0, err
	}

	logits := outT.GetData()
	if len(logits) < 2 {
		return 0, fmt.Errorf("unexpected dga output shape: %d", len(logits))
	}
	return softmax2(logits[0], logits[1]), nil
}

// ── Tranco greylist ───────────────────────────────────────────────────────────

func (o *ONNXScanner) loadTrancoEmbedded() error {
	data, err := embeddedModels.ReadFile("models/tranco-top10k.txt")
	if err != nil {
		return err
	}
	o.parseTranco(data)
	return nil
}

func (o *ONNXScanner) loadTrancoFile(path string) error {
	data, err := os.ReadFile(path) // #nosec G304 -- path is an operator-configured model/data file, not request input
	if err != nil {
		return err
	}
	o.parseTranco(data)
	return nil
}

func (o *ONNXScanner) parseTranco(data []byte) {
	lines := strings.Split(string(data), "\n")
	m := make(map[string]struct{}, len(lines))
	for _, line := range lines {
		d := strings.ToLower(strings.TrimSpace(line))
		if d != "" {
			m[d] = struct{}{}
		}
	}
	o.mu.Lock()
	o.tranco = m
	o.mu.Unlock()
}

// isTrancoGreylisted reports whether domain OR any of its parent registered
// domains appears in the Tranco top-10k list. Subdomain lookup prevents false
// positives on auth/CDN subdomains (e.g. accounts.google.com → google.com).
func (o *ONNXScanner) isTrancoGreylisted(domain string) bool {
	d := strings.ToLower(domain)
	o.mu.RLock()
	defer o.mu.RUnlock()
	for {
		if _, ok := o.tranco[d]; ok {
			return true
		}
		dot := strings.IndexByte(d, '.')
		if dot < 0 || strings.IndexByte(d[dot+1:], '.') < 0 {
			// Stop once we've reached the bare TLD — don't match ".com" alone.
			break
		}
		d = d[dot+1:]
	}
	return false
}

// ── Utilities ─────────────────────────────────────────────────────────────────

// encodeDomainChars maps domain characters to integer indices for the DGA CNN.
// Matches CHARS/CHAR2IDX in Reynier/dga-cnn model.py:
//
//	a-z → 1-26, 0-9 → 27-36, '-' → 37, '.' → 38, '_' → 39, unknown → 0 (padding)
func encodeDomainChars(domain string, maxLen int) []int64 {
	out := make([]int64, maxLen)
	for i, ch := range strings.ToLower(domain) {
		if i >= maxLen {
			break
		}
		switch {
		case ch >= 'a' && ch <= 'z':
			out[i] = int64(ch-'a') + 1
		case ch >= '0' && ch <= '9':
			out[i] = int64(ch-'0') + 27
		case ch == '-':
			out[i] = 37
		case ch == '.':
			out[i] = 38
		case ch == '_':
			out[i] = 39
		}
	}
	return out
}

// extractDomains returns deduplicated hostnames from a list of URLs.
func extractDomains(urls []string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, u := range urls {
		idx := strings.Index(u, "://")
		if idx < 0 {
			continue
		}
		rest := u[idx+3:]
		host := rest
		if slash := strings.IndexByte(rest, '/'); slash >= 0 {
			host = rest[:slash]
		}
		if colon := strings.LastIndexByte(host, ':'); colon >= 0 {
			host = host[:colon]
		}
		host = strings.ToLower(host)
		if host == "" {
			continue
		}
		if _, ok := seen[host]; !ok {
			seen[host] = struct{}{}
			out = append(out, host)
		}
	}
	return out
}

func softmax2(logit0, logit1 float32) float32 {
	e0 := float32(math.Exp(float64(logit0)))
	e1 := float32(math.Exp(float64(logit1)))
	return e1 / (e0 + e1)
}

// softmaxPhish computes the combined probability of the given phish class
// indices out of an N-class logit vector. Uses numerically stable softmax.
func softmaxPhish(logits []float32, phishIndices ...int) float32 {
	maxL := logits[0]
	for _, l := range logits {
		if l > maxL {
			maxL = l
		}
	}
	var sum, phish float32
	phishSet := make(map[int]struct{}, len(phishIndices))
	for _, i := range phishIndices {
		phishSet[i] = struct{}{}
	}
	for i, l := range logits {
		e := float32(math.Exp(float64(l - maxL)))
		sum += e
		if _, ok := phishSet[i]; ok {
			phish += e
		}
	}
	if sum == 0 {
		return 0
	}
	return phish / sum
}

// extractDomain returns the hostname from a single URL string.
func extractDomain(rawURL string) string {
	idx := strings.Index(rawURL, "://")
	if idx < 0 {
		return rawURL
	}
	rest := rawURL[idx+3:]
	host := rest
	if slash := strings.IndexByte(rest, '/'); slash >= 0 {
		host = rest[:slash]
	}
	if colon := strings.LastIndexByte(host, ':'); colon >= 0 {
		host = host[:colon]
	}
	return strings.ToLower(host)
}

func padOrTruncateInt(s []int, targetLen, padVal int) []int {
	out := make([]int, targetLen)
	n := len(s)
	if n > targetLen {
		n = targetLen
	}
	copy(out, s[:n])
	// remaining elements stay as padVal (zero value of int matches padVal=0)
	return out
}

func max32(a, b float32) float32 {
	if a > b {
		return a
	}
	return b
}
