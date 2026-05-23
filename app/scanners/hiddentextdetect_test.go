package scanners

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/izm1chael/mailhook/config"
	"github.com/izm1chael/mailhook/db"
	"github.com/izm1chael/mailhook/pipeline"
)

func newHiddenTextScanner(t *testing.T, enabled bool) *HiddenTextDetect {
	t.Helper()
	return NewHiddenTextDetect(&config.Config{HiddenTextEnabled: enabled}, newTestLogger())
}

func scanHTMLBody(t *testing.T, s *HiddenTextDetect, body string) ([]db.HiddenTextHit, string) {
	t.Helper()
	res := s.Scan(context.Background(), &pipeline.Email{HTMLBody: body})
	if res.Verdict == "suspicious" && len(res.Matches) > 0 {
		var hits []db.HiddenTextHit
		if err := json.Unmarshal(res.Matches, &hits); err != nil {
			t.Fatalf("unmarshal hits: %v", err)
		}
		return hits, res.Verdict
	}
	return nil, res.Verdict
}

func findTechnique(hits []db.HiddenTextHit, technique string) *db.HiddenTextHit {
	for i := range hits {
		if hits[i].Technique == technique {
			return &hits[i]
		}
	}
	return nil
}

func TestHiddenText_Disabled(t *testing.T) {
	s := newHiddenTextScanner(t, false)
	body := `<span style="font-size:0">hidden words here</span>`
	_, verdict := scanHTMLBody(t, s, body)
	if verdict != "skip" {
		t.Fatalf("expected skip when disabled, got %s", verdict)
	}
}

func TestHiddenText_EmptyBody(t *testing.T) {
	s := newHiddenTextScanner(t, true)
	res := s.Scan(context.Background(), &pipeline.Email{HTMLBody: ""})
	if res.Verdict != "skip" {
		t.Fatalf("expected skip for empty body, got %s", res.Verdict)
	}
}

func TestHiddenText_CleanHTML(t *testing.T) {
	s := newHiddenTextScanner(t, true)
	body := `<html><body><p style="color:red">Hello world</p></body></html>`
	_, verdict := scanHTMLBody(t, s, body)
	if verdict != "clean" {
		t.Fatalf("expected clean for normal HTML, got %s", verdict)
	}
}

func TestHiddenText_ZeroFont(t *testing.T) {
	s := newHiddenTextScanner(t, true)
	body := `<html><body><span style="font-size:0">apple banana cherry dictionary</span></body></html>`
	hits, verdict := scanHTMLBody(t, s, body)
	if verdict != "suspicious" {
		t.Fatalf("expected suspicious for font-size:0, got %s", verdict)
	}
	hit := findTechnique(hits, "zero_font")
	if hit == nil {
		t.Fatal("expected zero_font technique in hits")
	}
	if hit.Count < 1 {
		t.Errorf("expected count >= 1, got %d", hit.Count)
	}
	if hit.Sample == "" {
		t.Error("expected non-empty sample")
	}
}

func TestHiddenText_ZeroFontPx(t *testing.T) {
	s := newHiddenTextScanner(t, true)
	body := `<p style="font-size:0px">dictionary words evasion</p>`
	hits, verdict := scanHTMLBody(t, s, body)
	if verdict != "suspicious" {
		t.Fatalf("expected suspicious for font-size:0px, got %s", verdict)
	}
	if findTechnique(hits, "zero_font") == nil {
		t.Fatal("expected zero_font technique")
	}
}

func TestHiddenText_ZeroFontEm(t *testing.T) {
	s := newHiddenTextScanner(t, true)
	body := `<span style="font-size:0em">invisible text for spam</span>`
	hits, verdict := scanHTMLBody(t, s, body)
	if verdict != "suspicious" {
		t.Fatalf("expected suspicious for font-size:0em, got %s", verdict)
	}
	if findTechnique(hits, "zero_font") == nil {
		t.Fatal("expected zero_font technique")
	}
}

func TestHiddenText_DisplayNone(t *testing.T) {
	s := newHiddenTextScanner(t, true)
	body := `<div style="display:none">random bayes-poisoning words</div>`
	hits, verdict := scanHTMLBody(t, s, body)
	if verdict != "suspicious" {
		t.Fatalf("expected suspicious for display:none, got %s", verdict)
	}
	if findTechnique(hits, "display_none") == nil {
		t.Fatal("expected display_none technique")
	}
}

func TestHiddenText_DisplayNoneWithSpaces(t *testing.T) {
	s := newHiddenTextScanner(t, true)
	body := `<p style="display: none ; color:red">hidden content here</p>`
	hits, verdict := scanHTMLBody(t, s, body)
	if verdict != "suspicious" {
		t.Fatalf("expected suspicious for display: none with spaces, got %s", verdict)
	}
	if findTechnique(hits, "display_none") == nil {
		t.Fatal("expected display_none technique")
	}
}

func TestHiddenText_VisibilityHidden(t *testing.T) {
	s := newHiddenTextScanner(t, true)
	body := `<span style="visibility:hidden">spam filler text here</span>`
	hits, verdict := scanHTMLBody(t, s, body)
	if verdict != "suspicious" {
		t.Fatalf("expected suspicious for visibility:hidden, got %s", verdict)
	}
	if findTechnique(hits, "visibility_hidden") == nil {
		t.Fatal("expected visibility_hidden technique")
	}
}

func TestHiddenText_OpacityZero(t *testing.T) {
	s := newHiddenTextScanner(t, true)
	body := `<p style="opacity:0">transparent text evasion here</p>`
	hits, verdict := scanHTMLBody(t, s, body)
	if verdict != "suspicious" {
		t.Fatalf("expected suspicious for opacity:0, got %s", verdict)
	}
	if findTechnique(hits, "opacity_zero") == nil {
		t.Fatal("expected opacity_zero technique")
	}
}

func TestHiddenText_ColorMatch(t *testing.T) {
	s := newHiddenTextScanner(t, true)
	body := `<p style="color:#ffffff;background-color:#ffffff">invisible on white</p>`
	hits, verdict := scanHTMLBody(t, s, body)
	if verdict != "suspicious" {
		t.Fatalf("expected suspicious for color match, got %s", verdict)
	}
	if findTechnique(hits, "color_match") == nil {
		t.Fatal("expected color_match technique")
	}
}

func TestHiddenText_ColorMatchCaseInsensitive(t *testing.T) {
	s := newHiddenTextScanner(t, true)
	body := `<p style="color:#FFFFFF;background-color:#ffffff">invisible text</p>`
	hits, verdict := scanHTMLBody(t, s, body)
	if verdict != "suspicious" {
		t.Fatalf("expected suspicious for case-insensitive color match, got %s", verdict)
	}
	if findTechnique(hits, "color_match") == nil {
		t.Fatal("expected color_match technique")
	}
}

func TestHiddenText_DifferentColors_Clean(t *testing.T) {
	s := newHiddenTextScanner(t, true)
	// Black text on white — legitimate, not a color match
	body := `<p style="color:#000000;background-color:#ffffff">visible text</p>`
	_, verdict := scanHTMLBody(t, s, body)
	if verdict != "clean" {
		t.Fatalf("different colors should be clean, got %s", verdict)
	}
}

func TestHiddenText_EmptyElement_Clean(t *testing.T) {
	// Element with hiding style but no text content → not an evasion attempt
	s := newHiddenTextScanner(t, true)
	body := `<span style="font-size:0"></span>`
	_, verdict := scanHTMLBody(t, s, body)
	if verdict != "clean" {
		t.Fatalf("hiding style on empty element should be clean, got %s", verdict)
	}
}

func TestHiddenText_WhitespaceOnlyElement_Clean(t *testing.T) {
	s := newHiddenTextScanner(t, true)
	body := `<span style="display:none">   </span>`
	_, verdict := scanHTMLBody(t, s, body)
	if verdict != "clean" {
		t.Fatalf("hiding style on whitespace-only element should be clean, got %s", verdict)
	}
}

func TestHiddenText_MultipleTechniques(t *testing.T) {
	s := newHiddenTextScanner(t, true)
	body := `<html><body>
		<span style="font-size:0">zero font hidden text</span>
		<div style="display:none">display none hidden text</div>
		<p style="visibility:hidden">visibility hidden text</p>
	</body></html>`
	hits, verdict := scanHTMLBody(t, s, body)
	if verdict != "suspicious" {
		t.Fatalf("expected suspicious for multiple techniques, got %s", verdict)
	}
	if len(hits) < 3 {
		t.Fatalf("expected at least 3 technique hits, got %d", len(hits))
	}
}

func TestHiddenText_MultipleElements_CountAggregated(t *testing.T) {
	// Two elements with font-size:0 → count should be 2
	s := newHiddenTextScanner(t, true)
	body := `<html><body>
		<span style="font-size:0">first hidden block of words</span>
		<span style="font-size:0">second hidden block of words</span>
	</body></html>`
	hits, verdict := scanHTMLBody(t, s, body)
	if verdict != "suspicious" {
		t.Fatalf("expected suspicious, got %s", verdict)
	}
	hit := findTechnique(hits, "zero_font")
	if hit == nil {
		t.Fatal("expected zero_font technique")
	}
	if hit.Count < 2 {
		t.Errorf("expected count >= 2 for two hidden elements, got %d", hit.Count)
	}
}

func TestHiddenText_FontSizeZeroTag(t *testing.T) {
	// <font size="0"> element
	s := newHiddenTextScanner(t, true)
	body := `<html><body><font size="0">hidden words fruit vegetable</font></body></html>`
	hits, verdict := scanHTMLBody(t, s, body)
	if verdict != "suspicious" {
		t.Fatalf("expected suspicious for <font size=0>, got %s", verdict)
	}
	if findTechnique(hits, "zero_font") == nil {
		t.Fatal("expected zero_font technique from <font size=0>")
	}
}

func TestHiddenText_SampleTruncated(t *testing.T) {
	// Sample should be truncated to 80 chars
	s := newHiddenTextScanner(t, true)
	longText := strings.Repeat("word ", 50)
	body := `<span style="font-size:0">` + longText + `</span>`
	hits, verdict := scanHTMLBody(t, s, body)
	if verdict != "suspicious" {
		t.Fatalf("expected suspicious, got %s", verdict)
	}
	hit := findTechnique(hits, "zero_font")
	if hit == nil {
		t.Fatal("expected zero_font technique")
	}
	if len(hit.Sample) > 80 {
		t.Errorf("sample should be truncated to 80 chars, got %d: %q", len(hit.Sample), hit.Sample)
	}
}

func TestHiddenText_SetEnabled(t *testing.T) {
	s := newHiddenTextScanner(t, true)
	if !s.IsEnabled() {
		t.Fatal("expected enabled")
	}
	s.SetEnabled(false)
	if s.IsEnabled() {
		t.Fatal("expected disabled after SetEnabled(false)")
	}
	body := `<span style="font-size:0">hidden</span>`
	res := s.Scan(context.Background(), &pipeline.Email{HTMLBody: body})
	if res.Verdict != "skip" {
		t.Fatalf("expected skip after disable, got %s", res.Verdict)
	}
}

func TestHiddenText_MatchesJSON_Struct(t *testing.T) {
	s := newHiddenTextScanner(t, true)
	body := `<span style="display:none">bayes poisoning text</span>`
	res := s.Scan(context.Background(), &pipeline.Email{HTMLBody: body})
	if res.Verdict != "suspicious" {
		t.Fatalf("expected suspicious, got %s", res.Verdict)
	}

	var hits []db.HiddenTextHit
	if err := json.Unmarshal(res.Matches, &hits); err != nil {
		t.Fatalf("Matches is not valid []db.HiddenTextHit JSON: %v", err)
	}
	if len(hits) == 0 {
		t.Fatal("expected at least one hit")
	}
	hit := hits[0]
	if hit.Technique == "" {
		t.Error("Technique must not be empty")
	}
	if hit.Count <= 0 {
		t.Error("Count must be positive")
	}
}
