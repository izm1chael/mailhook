package scanners

import (
	"context"
	"encoding/json"
	"log/slog"
	"regexp"
	"strings"
	"sync"

	"github.com/izm1chael/mailhook/config"
	"github.com/izm1chael/mailhook/db"
	"github.com/izm1chael/mailhook/pipeline"
)

// b64ChunkRe matches runs of base64 characters long enough to encode meaningful data.
// 200 characters ≈ 150 bytes of binary — used only to locate candidate blobs;
// the minimum-size check is applied separately using cfg.HTMLSmugglingMinB64KB.
var b64ChunkRe = regexp.MustCompile(`[A-Za-z0-9+/]{200,}={0,2}`)

// blobAPIs lists JavaScript Blob-related API patterns and their display names.
// Detection requires at least one match from this list in the same source as the
// large base64 blob, confirming intent to reconstruct a file client-side.
var blobAPIs = []struct {
	name string
	re   *regexp.Regexp
}{
	{"new Blob(", regexp.MustCompile(`new\s+Blob\s*\(`)},
	{"msSaveOrOpenBlob", regexp.MustCompile(`msSaveOrOpenBlob`)},
	{"createObjectURL", regexp.MustCompile(`createObjectURL`)},
	{"saveAs(", regexp.MustCompile(`saveAs\s*\(`)},
}

// HTMLSmuggling detects HTML smuggling payloads — large Base64 blobs combined with
// Blob-reconstruction JavaScript — inside HTML attachments and the HTML email body.
type HTMLSmuggling struct {
	mu        sync.RWMutex
	enabled   bool
	minB64KB  int
	log       *slog.Logger
}

// NewHTMLSmuggling creates an HTMLSmuggling scanner.
func NewHTMLSmuggling(cfg *config.Config, log *slog.Logger) *HTMLSmuggling {
	return &HTMLSmuggling{
		enabled:  cfg.HTMLSmugglingEnabled,
		minB64KB: cfg.HTMLSmugglingMinB64KB,
		log:      log,
	}
}

func (h *HTMLSmuggling) Name() string { return "htmlsmuggling" }

// SetEnabled enables or disables the scanner at runtime.
func (h *HTMLSmuggling) SetEnabled(v bool) { h.mu.Lock(); h.enabled = v; h.mu.Unlock() }

// IsEnabled reports whether the scanner is currently enabled.
func (h *HTMLSmuggling) IsEnabled() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.enabled }

// Scan checks HTML attachments and the HTML body for smuggling indicators.
// A hit requires both a large base64 blob and at least one Blob API call in the
// same source, preventing false positives from newsletters with inline images.
func (h *HTMLSmuggling) Scan(ctx context.Context, email *pipeline.Email) pipeline.ScanResult {
	h.mu.RLock()
	enabled := h.enabled
	minB64KB := h.minB64KB
	h.mu.RUnlock()

	if !enabled {
		return pipeline.ScanResult{Scanner: h.Name(), Verdict: "skip", Detail: "disabled"}
	}
	if ctx.Err() != nil {
		return pipeline.ScanResult{Scanner: h.Name(), Verdict: "skip", Detail: "context cancelled"}
	}

	type source struct {
		label   string
		content []byte
	}

	var sources []source

	// HTML body
	if email.HTMLBody != "" {
		sources = append(sources, source{"body", []byte(email.HTMLBody)})
	}

	// HTML attachments
	for _, att := range email.Attachments {
		if isHTMLAttachment(att) {
			sources = append(sources, source{"attachment:" + att.Filename, att.Raw})
		}
	}

	if len(sources) == 0 {
		return pipeline.ScanResult{Scanner: h.Name(), Verdict: "clean"}
	}

	// b64MinChars: number of base64 chars that encode minB64KB of binary data.
	// base64 expands data by 4/3, so binary bytes = chars * 3 / 4.
	b64MinChars := minB64KB * 1024 * 4 / 3

	var hits []db.HTMLSmugglingHit

	for _, src := range sources {
		largestB64, b64SizeKB := largestBase64Chunk(src.content, b64MinChars)
		if largestB64 == 0 {
			continue
		}

		var matchedAPIs []string
		for _, api := range blobAPIs {
			if api.re.Match(src.content) {
				matchedAPIs = append(matchedAPIs, api.name)
			}
		}
		if len(matchedAPIs) == 0 {
			continue
		}

		hits = append(hits, db.HTMLSmugglingHit{
			Source:    src.label,
			BlobAPIs:  matchedAPIs,
			B64SizeKB: b64SizeKB,
		})
	}

	if len(hits) == 0 {
		return pipeline.ScanResult{Scanner: h.Name(), Verdict: "clean"}
	}

	matchData, _ := json.Marshal(hits)

	var parts []string
	for _, hit := range hits {
		parts = append(parts, hit.Source+": "+strings.Join(hit.BlobAPIs, ", "))
	}
	detail := "HTML smuggling: " + strings.Join(parts, "; ")
	if len(detail) > 500 {
		detail = detail[:500] + "…"
	}

	return pipeline.ScanResult{
		Scanner: h.Name(),
		Verdict: "suspicious",
		Score:   0.80,
		Detail:  detail,
		Matches: matchData,
	}
}

// largestBase64Chunk returns the character length and approximate KB size of the
// largest base64 blob found in content that meets the minimum character threshold.
// Returns 0, 0 if no blob exceeds the threshold.
func largestBase64Chunk(content []byte, minChars int) (maxChars int, sizeKB int) {
	matches := b64ChunkRe.FindAll(content, -1)
	for _, m := range matches {
		if len(m) > maxChars {
			maxChars = len(m)
		}
	}
	if maxChars < minChars {
		return 0, 0
	}
	// Convert base64 character count to approximate binary KB.
	sizeKB = maxChars * 3 / 4 / 1024
	if sizeKB == 0 {
		sizeKB = 1
	}
	return maxChars, sizeKB
}

// isHTMLAttachment reports whether an attachment is HTML content.
func isHTMLAttachment(att pipeline.Attachment) bool {
	if strings.HasPrefix(att.ContentType, "text/html") {
		return true
	}
	ext := strings.ToLower(att.Extension)
	return ext == ".html" || ext == ".htm"
}
