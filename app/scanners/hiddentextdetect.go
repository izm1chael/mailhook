package scanners

import (
	"context"
	"encoding/json"
	"log/slog"
	"regexp"
	"strings"
	"sync"

	"github.com/PuerkitoBio/goquery"
	"github.com/izm1chael/mailhook/config"
	"github.com/izm1chael/mailhook/db"
	"github.com/izm1chael/mailhook/pipeline"
)

// CSS hiding technique patterns applied to inline style attribute values.
var (
	htZeroFontRe         = regexp.MustCompile(`(?i)font-size\s*:\s*0(?:px|em|rem|pt|%)?(?:[;\s"']|$)`)
	htDisplayNoneRe      = regexp.MustCompile(`(?i)display\s*:\s*none(?:[;\s"']|$)`)
	htVisibilityHiddenRe = regexp.MustCompile(`(?i)visibility\s*:\s*hidden(?:[;\s"']|$)`)
	htOpacityZeroRe      = regexp.MustCompile(`(?i)opacity\s*:\s*0(?:\.\s*0*)?(?:[;\s"']|$)`)
	htColorRe            = regexp.MustCompile(`(?i)(?:^|[;\s])color\s*:\s*(#[0-9a-fA-F]{3,8})`)
	htBgColorRe          = regexp.MustCompile(`(?i)background(?:-color)?\s*:\s*(#[0-9a-fA-F]{3,8})`)
)

// HiddenTextDetect detects hidden text evasion techniques inside the HTML email body:
// zero-font sizes, display:none, visibility:hidden, opacity:0, and color-on-background
// matching (text the same color as the background).
type HiddenTextDetect struct {
	mu      sync.RWMutex
	enabled bool
	log     *slog.Logger
}

// NewHiddenTextDetect creates a HiddenTextDetect scanner.
func NewHiddenTextDetect(cfg *config.Config, log *slog.Logger) *HiddenTextDetect {
	return &HiddenTextDetect{
		enabled: cfg.HiddenTextEnabled,
		log:     log,
	}
}

func (h *HiddenTextDetect) Name() string { return "hiddentextdetect" }

// SetEnabled enables or disables the scanner at runtime.
func (h *HiddenTextDetect) SetEnabled(v bool) { h.mu.Lock(); h.enabled = v; h.mu.Unlock() }

// IsEnabled reports whether the scanner is currently enabled.
func (h *HiddenTextDetect) IsEnabled() bool { h.mu.RLock(); defer h.mu.RUnlock(); return h.enabled }

// Scan parses the HTML body and reports any CSS hiding techniques applied to
// elements that contain non-whitespace text content.
func (h *HiddenTextDetect) Scan(ctx context.Context, email *pipeline.Email) pipeline.ScanResult {
	h.mu.RLock()
	enabled := h.enabled
	h.mu.RUnlock()

	if !enabled {
		return pipeline.ScanResult{Scanner: h.Name(), Verdict: "skip", Detail: "disabled"}
	}
	if email.HTMLBody == "" {
		return pipeline.ScanResult{Scanner: h.Name(), Verdict: "skip", Detail: "no HTML body"}
	}
	if ctx.Err() != nil {
		return pipeline.ScanResult{Scanner: h.Name(), Verdict: "skip", Detail: "context cancelled"}
	}

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(email.HTMLBody))
	if err != nil {
		h.log.Debug("hiddentextdetect: HTML parse error", "err", err)
		return pipeline.ScanResult{Scanner: h.Name(), Verdict: "clean"}
	}

	// counts maps technique name → {count, first sample text}
	type techniqueInfo struct {
		count  int
		sample string
	}
	counts := make(map[string]*techniqueInfo)

	record := func(technique, text string) {
		info, ok := counts[technique]
		if !ok {
			sample := strings.TrimSpace(text)
			if len(sample) > 80 {
				sample = sample[:80]
			}
			counts[technique] = &techniqueInfo{count: 1, sample: sample}
		} else {
			info.count++
		}
	}

	// Walk all elements with a style attribute.
	doc.Find("[style]").Each(func(_ int, s *goquery.Selection) {
		style, _ := s.Attr("style")
		if style == "" {
			return
		}
		text := strings.TrimSpace(s.Text())
		if text == "" {
			return // no text to hide — not an evasion attempt
		}

		if htZeroFontRe.MatchString(style) {
			record("zero_font", text)
		}
		if htDisplayNoneRe.MatchString(style) {
			record("display_none", text)
		}
		if htVisibilityHiddenRe.MatchString(style) {
			record("visibility_hidden", text)
		}
		if htOpacityZeroRe.MatchString(style) {
			record("opacity_zero", text)
		}
		if isColorMatch(style) {
			record("color_match", text)
		}
	})

	// Also check <font size="0"> and <font color=...> elements.
	doc.Find("font[size]").Each(func(_ int, s *goquery.Selection) {
		size, _ := s.Attr("size")
		text := strings.TrimSpace(s.Text())
		if text == "" {
			return
		}
		size = strings.TrimSpace(size)
		if size == "0" || size == "1" {
			record("zero_font", text)
		}
	})

	if len(counts) == 0 {
		return pipeline.ScanResult{Scanner: h.Name(), Verdict: "clean"}
	}

	var hits []db.HiddenTextHit
	var techniques []string
	for technique, info := range counts {
		hits = append(hits, db.HiddenTextHit{
			Technique: technique,
			Count:     info.count,
			Sample:    info.sample,
		})
		techniques = append(techniques, technique)
	}

	matchData, _ := json.Marshal(hits)
	detail := "hidden text: " + strings.Join(techniques, ", ")

	return pipeline.ScanResult{
		Scanner: h.Name(),
		Verdict: "suspicious",
		Score:   0.50,
		Detail:  detail,
		Matches: matchData,
	}
}

var (
	htColorNamedRe  = regexp.MustCompile(`(?i)(?:^|[;\s])color\s*:\s*([a-zA-Z]+)`)
	htBgColorNamedRe = regexp.MustCompile(`(?i)background(?:-color)?\s*:\s*([a-zA-Z]+)`)
	htColorRGBRe    = regexp.MustCompile(`(?i)(?:^|[;\s])color\s*:\s*(rgba?\([^)]+\))`)
	htBgColorRGBRe  = regexp.MustCompile(`(?i)background(?:-color)?\s*:\s*(rgba?\([^)]+\))`)
)

// namedColorHex maps common named colors to their hex equivalent for comparison.
var namedColorHex = map[string]string{
	"white": "ffffff", "black": "000000", "red": "ff0000",
	"green": "008000", "blue": "0000ff", "yellow": "ffff00",
	"orange": "ffa500", "purple": "800080", "gray": "808080",
	"grey": "808080", "silver": "c0c0c0", "transparent": "transparent",
}

// isColorMatch reports whether the inline style has a text color that exactly
// matches the background color. Supports hex, named colors, and rgb()/rgba().
func isColorMatch(style string) bool {
	fg := extractColorValue(style, htColorRe, htColorNamedRe, htColorRGBRe)
	bg := extractColorValue(style, htBgColorRe, htBgColorNamedRe, htBgColorRGBRe)
	if fg == "" || bg == "" {
		return false
	}
	return strings.EqualFold(normalizeColor(fg), normalizeColor(bg))
}

func extractColorValue(style string, hexRe, namedRe, rgbRe *regexp.Regexp) string {
	if m := hexRe.FindStringSubmatch(style); len(m) >= 2 {
		return m[1]
	}
	if m := rgbRe.FindStringSubmatch(style); len(m) >= 2 {
		return m[1]
	}
	if m := namedRe.FindStringSubmatch(style); len(m) >= 2 {
		return strings.ToLower(m[1])
	}
	return ""
}

func normalizeColor(c string) string {
	c = strings.ToLower(c)
	if hex, ok := namedColorHex[c]; ok {
		return hex
	}
	if strings.HasPrefix(c, "#") {
		return normalizeHex(c)
	}
	// Normalize rgb() by removing whitespace for comparison.
	c = regexp.MustCompile(`\s+`).ReplaceAllString(c, "")
	return c
}

// normalizeHex expands 3-digit hex (#abc) to 6-digit (#aabbcc) for comparison.
func normalizeHex(hex string) string {
	hex = strings.ToLower(strings.TrimPrefix(hex, "#"))
	if len(hex) == 3 {
		return string([]byte{hex[0], hex[0], hex[1], hex[1], hex[2], hex[2]})
	}
	return hex
}

