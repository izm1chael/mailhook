package pipeline

import (
	"bytes"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"log/slog"
	"net"
	"regexp"
	"strings"
	"time"

	"net/url"

	"github.com/PuerkitoBio/goquery"
	"github.com/emersion/go-message/mail"
	"github.com/izm1chael/mailhook/util"
	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/qrcode"
)

// Attachment holds a decoded MIME attachment and its computed metadata.
type Attachment struct {
	Filename    string
	ContentType string
	SHA256      string
	Extension   string
	SizeBytes   int64
	IsDangerous bool
	Raw         []byte
}

// Email is the in-flight representation of a message as it moves through the pipeline.
// It is constructed once by Parse and is read-only during the scanner fan-out phase.
type Email struct {
	// IMAP context
	AccountName string
	IMAPUID     uint32
	IMAPMailbox string

	// Identity
	Raw       []byte
	MessageID string
	Subject   string
	From      string
	To        string
	Date      time.Time
	SizeBytes int64

	// Authentication headers (raw values from the message headers)
	SPFResult   string
	DKIMResult  string
	DMARCResult string

	// Extracted content
	TextBody    string
	HTMLBody    string
	URLs        []string  // deduplicated, normalized
	Attachments []Attachment
	SenderIPs   []net.IP  // public IPs from Received headers, bottom-up

	HasExecutable  bool   // true if any attachment is an executable type
	WhitelistEntry string // set by pipeline if sender is whitelisted (bypass_scan=false)
	HadMIMEErrors  bool   // true if one or more MIME parts failed to parse (analysis may be incomplete)
}

var trackingParams = []string{
	"utm_source", "utm_medium", "utm_campaign", "utm_content", "utm_term",
	"fbclid", "gclid", "mc_eid", "yclid", "twclid",
}

// Parse builds an Email from raw RFC822 bytes and IMAP context metadata.
// maxAttachmentBytes caps total in-memory attachment bytes; 0 means unlimited.
func Parse(raw []byte, accountName string, uid uint32, mailbox string, maxAttachmentBytes int64, trustedAuthservID string) (*Email, error) {
	mr, err := mail.CreateReader(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}

	h := mr.Header
	email := &Email{
		Raw:         raw,
		AccountName: accountName,
		IMAPUID:     uid,
		IMAPMailbox: mailbox,
		SizeBytes:   int64(len(raw)),
	}

	email.MessageID, _ = h.MessageID()
	email.Subject, _ = h.Subject()
	if from, err := h.AddressList("From"); err == nil && len(from) > 0 {
		email.From = from[0].String()
	}
	if to, err := h.AddressList("To"); err == nil {
		addrs := make([]string, len(to))
		for i, a := range to {
			addrs[i] = a.String()
		}
		email.To = strings.Join(addrs, ", ")
	}
	if date, err := h.Date(); err == nil {
		email.Date = date
	}

	email.SPFResult = extractAuthResult(h, "spf", trustedAuthservID)
	email.DKIMResult = extractAuthResult(h, "dkim", trustedAuthservID)
	email.DMARCResult = extractAuthResult(h, "dmarc", trustedAuthservID)

	// Extract sending IP from Received headers — bottom-up per plan to avoid forgery
	var receivedHeaders []string
	fields := h.FieldsByKey("Received")
	for fields.Next() {
		receivedHeaders = append(receivedHeaders, fields.Value())
	}
	if ip := util.ExtractSendingIP(receivedHeaders); ip != nil {
		email.SenderIPs = []net.IP{ip}
	}

	// Walk MIME parts
	const maxTotalBodyBytes = 20 * 1024 * 1024 // 20 MB aggregate inline body cap
	var totalAttachmentBytes int64
	var totalBodyBytes int64
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			slog.Debug("MIME part error — skipping part", "uid", uid, "err", err)
			email.HadMIMEErrors = true
			continue
		}

		switch ph := part.Header.(type) {
		case *mail.InlineHeader:
			ct, _, _ := ph.ContentType()
			remaining := maxTotalBodyBytes - totalBodyBytes
			if remaining <= 0 {
				slog.Debug("inline body aggregate cap reached, skipping part", "uid", uid)
				continue
			}
			body, _ := io.ReadAll(io.LimitReader(part.Body, min(10*1024*1024, remaining)))
			totalBodyBytes += int64(len(body))
			switch {
			case strings.HasPrefix(ct, "text/plain"):
				email.TextBody += string(body)
			case strings.HasPrefix(ct, "text/html"):
				email.HTMLBody += string(body)
			}

		case *mail.AttachmentHeader:
			// Compute the per-attachment read budget so we never read past the total cap.
			budget := int64(50 * 1024 * 1024) // 50 MB hard per-attachment limit
			if maxAttachmentBytes > 0 {
				remaining := maxAttachmentBytes - totalAttachmentBytes
				if remaining <= 0 {
					slog.Debug("attachment total size cap reached, skipping remaining", "uid", uid)
					continue
				}
				if remaining < budget {
					budget = remaining
				}
			}
			att := buildAttachment(ph, part.Body, budget)
			if att != nil {
				totalAttachmentBytes += att.SizeBytes
				email.Attachments = append(email.Attachments, *att)
				if att.IsDangerous {
					email.HasExecutable = true
				}
			}
		}
	}

	email.URLs = extractURLs(email.TextBody, email.HTMLBody)
	if qrURLs := extractQRURLs(email.Attachments); len(qrURLs) > 0 {
		seen := make(map[string]bool, len(email.URLs))
		for _, u := range email.URLs {
			seen[u] = true
		}
		for _, u := range qrURLs {
			if !seen[u] {
				seen[u] = true
				email.URLs = append(email.URLs, u)
			}
		}
	}
	return email, nil
}

func buildAttachment(h *mail.AttachmentHeader, body io.Reader, maxBytes int64) *Attachment {
	filename, _ := h.Filename()
	if filename == "" {
		ct, params, _ := h.ContentType()
		filename = params["name"]
		if filename == "" {
			filename = "attachment." + strings.Split(ct, "/")[len(strings.Split(ct, "/"))-1]
		}
	}

	raw, err := io.ReadAll(io.LimitReader(body, maxBytes))
	if err != nil {
		return nil
	}

	ct, _, _ := h.ContentType()
	ext := strings.ToLower(fileExt(filename))

	att := &Attachment{
		Filename:    filename,
		ContentType: util.SafeContentType(ct),
		Extension:   ext,
		SizeBytes:   int64(len(raw)),
		SHA256:      util.SHA256Hex(raw),
		IsDangerous: util.DangerousExtension(filename) || util.IsExecutable(ct),
		Raw:         raw,
	}
	return att
}

const maxURLsPerEmail = 100

var urlRegex = regexp.MustCompile(`https?://[^\s"'<>()\[\]]+`)

func extractURLs(text, htmlBody string) []string {
	seen := make(map[string]bool)
	var urls []string

	addURL := func(raw string) bool {
		if len(urls) >= maxURLsPerEmail {
			return false
		}
		normalized := normalizeURL(raw)
		if normalized != "" && !seen[normalized] {
			seen[normalized] = true
			urls = append(urls, normalized)
		}
		// If this URL is a security gateway wrapper, also extract and add the real destination.
		// This ensures urlcheck, urlunshorten, and nrdcheck all see the true target URL.
		if decoded, ok := decodeSafeLink(raw); ok && decoded != "" {
			if dnorm := normalizeURL(decoded); dnorm != "" && !seen[dnorm] {
				if len(urls) >= maxURLsPerEmail {
					slog.Debug("URL cap reached, truncating extracted URLs")
					return false
				}
				seen[dnorm] = true
				urls = append(urls, dnorm)
			}
		}
		return true
	}

	// Plain text URLs
	for _, u := range urlRegex.FindAllString(text, -1) {
		if !addURL(u) {
			slog.Debug("URL cap reached in plain text", "cap", maxURLsPerEmail)
			break
		}
	}

	// HTML href/src attributes
	if len(urls) < maxURLsPerEmail {
		if doc, err := goquery.NewDocumentFromReader(strings.NewReader(htmlBody)); err == nil {
			capped := false
			doc.Find("[href],[src],[action]").Each(func(_ int, s *goquery.Selection) {
				if capped {
					return
				}
				for _, attr := range []string{"href", "src", "action"} {
					if val, exists := s.Attr(attr); exists && strings.HasPrefix(val, "http") {
						if !addURL(val) {
							slog.Debug("URL cap reached in HTML body", "cap", maxURLsPerEmail)
							capped = true
							return
						}
					}
				}
			})
		}
	}

	return urls
}

const qrMaxImageBytes = 2 * 1024 * 1024 // 2 MB

var qrImageMIMEs = map[string]bool{
	"image/png":  true,
	"image/jpeg": true,
	"image/jpg":  true,
	"image/gif":  true,
}

func extractQRURLs(atts []Attachment) []string {
	reader := qrcode.NewQRCodeReader()
	var results []string

	for _, att := range atts {
		ct := strings.ToLower(strings.TrimSpace(att.ContentType))
		if idx := strings.IndexByte(ct, ';'); idx >= 0 {
			ct = strings.TrimSpace(ct[:idx])
		}
		if !qrImageMIMEs[ct] {
			continue
		}
		if att.SizeBytes > qrMaxImageBytes {
			continue
		}
		if len(att.Raw) == 0 {
			continue
		}

		// Reject oversized images before allocating the full bitmap (decompression-bomb protection).
		cfg, _, err := image.DecodeConfig(bytes.NewReader(att.Raw))
		if err != nil {
			continue
		}
		const maxImageDimension = 4096
		if cfg.Width > maxImageDimension || cfg.Height > maxImageDimension {
			slog.Debug("QR image too large, skipping", "width", cfg.Width, "height", cfg.Height)
			continue
		}

		img, _, err := image.Decode(bytes.NewReader(att.Raw))
		if err != nil {
			continue
		}

		bmp, err := gozxing.NewBinaryBitmapFromImage(img)
		if err != nil {
			continue
		}

		result, err := reader.Decode(bmp, nil)
		if err != nil {
			continue
		}

		text := strings.TrimSpace(result.GetText())
		if text == "" {
			continue
		}

		if !strings.HasPrefix(text, "http://") && !strings.HasPrefix(text, "https://") {
			continue
		}

		if norm := normalizeURL(text); norm != "" {
			results = append(results, norm)
		}
	}

	return results
}

func normalizeURL(rawURL string) string {
	// Strip trailing punctuation that may have been captured by the regex
	rawURL = strings.TrimRight(rawURL, ".,;:!?\"'")

	// Only lowercase scheme and host — path/query are case-sensitive per RFC 3986.
	// Lowercasing the full URL causes feed-lookup misses for entries with mixed-case paths.
	parsed, err := url.Parse(rawURL)
	if err == nil {
		parsed.Scheme = strings.ToLower(parsed.Scheme)
		parsed.Host = strings.ToLower(parsed.Host)
		rawURL = parsed.String()
	}

	// Remove tracking parameters while preserving path/query case.
	idx := strings.IndexByte(rawURL, '?')
	if idx < 0 {
		return rawURL
	}
	base := rawURL[:idx]
	query := rawURL[idx+1:]

	var parts []string
	for _, kv := range strings.Split(query, "&") {
		key := kv
		if eq := strings.IndexByte(kv, '='); eq >= 0 {
			key = kv[:eq]
		}
		isTracking := false
		for _, tp := range trackingParams {
			if strings.EqualFold(key, tp) {
				isTracking = true
				break
			}
		}
		if !isTracking {
			parts = append(parts, kv)
		}
	}
	if len(parts) == 0 {
		return base
	}
	return base + "?" + strings.Join(parts, "&")
}

// extractAuthResult finds the result keyword for the given mechanism (spf/dkim/dmarc)
// from an Authentication-Results header. If trustedAuthservID is non-empty, only
// headers whose authserv-id matches are considered; others are ignored to prevent
// clients from injecting forged authentication results.
func extractAuthResult(h mail.Header, mechanism, trustedAuthservID string) string {
	fields := h.FieldsByKey("Authentication-Results")
	for fields.Next() {
		ar := fields.Value()
		if ar == "" {
			continue
		}
		// Check authserv-id: it is the first token before whitespace or semicolon.
		if trustedAuthservID != "" {
			firstToken := strings.FieldsFunc(ar, func(r rune) bool {
				return r == ' ' || r == '\t' || r == ';'
			})
			if len(firstToken) == 0 {
				continue
			}
			if !strings.EqualFold(firstToken[0], trustedAuthservID) {
				continue
			}
		}
		lower := strings.ToLower(ar)
		idx := strings.Index(lower, mechanism+"=")
		if idx < 0 {
			continue
		}
		rest := ar[idx+len(mechanism)+1:]
		end := strings.IndexAny(rest, " \t\r\n;")
		if end < 0 {
			return strings.ToLower(strings.TrimSpace(rest))
		}
		return strings.ToLower(strings.TrimSpace(rest[:end]))
	}
	return "none"
}

func fileExt(filename string) string {
	idx := strings.LastIndexByte(filename, '.')
	if idx < 0 {
		return ""
	}
	return filename[idx:]
}
