package util

import (
	"bytes"
	"io"
	"strings"

	"github.com/emersion/go-message/mail"
	"github.com/microcosm-cc/bluemonday"
)

var strictPolicy = bluemonday.StrictPolicy()
var ugcPolicy = bluemonday.UGCPolicy()

// SanitiseHTML strips all HTML tags and attributes, returning plain text.
func SanitiseHTML(raw string) string {
	return strictPolicy.Sanitize(raw)
}


// ExtractAndSanitizeHTML parses raw EML bytes, extracts the HTML body (falling
// back to plain text), sanitizes it through bluemonday UGCPolicy, and returns
// a safe HTML string suitable for embedding in a sandboxed iframe preview.
func ExtractAndSanitizeHTML(raw []byte) string {
	mr, err := mail.CreateReader(bytes.NewReader(raw))
	if err != nil {
		return "<p><em>Unable to parse email.</em></p>"
	}

	var htmlPart, textPart string
	for {
		p, err := mr.NextPart()
		if err != nil {
			break
		}
		ct := p.Header.Get("Content-Type")
		body, rerr := io.ReadAll(io.LimitReader(p.Body, 2<<20)) // 2MB cap
		if rerr != nil {
			continue
		}
		if strings.HasPrefix(ct, "text/html") && htmlPart == "" {
			htmlPart = ugcPolicy.Sanitize(string(body))
		} else if strings.HasPrefix(ct, "text/plain") && textPart == "" {
			textPart = "<pre>" + strictPolicy.Sanitize(string(body)) + "</pre>"
		}
	}

	if htmlPart != "" {
		return htmlPart
	}
	if textPart != "" {
		return textPart
	}
	return "<p><em>No readable content found.</em></p>"
}
