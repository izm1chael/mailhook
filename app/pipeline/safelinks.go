package pipeline

import (
	"net/url"
	"regexp"
	"strings"
)

// decodeSafeLink detects URLs wrapped by known email security gateway proxies
// and extracts the real destination URL. Returns the decoded URL and true if
// a known wrapper was detected; otherwise returns "", false.
//
// Supported wrappers:
//   - Microsoft ATP Safe Links (safelinks.protection.outlook.com)
//   - Proofpoint URLDefense v2 (urldefense.proofpoint.com)
//   - Proofpoint URLDefense v3 (urldefense.com)
//   - Mimecast URL Protection (mimecastprotect.com)
func decodeSafeLink(rawURL string) (string, bool) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", false
	}

	host := strings.ToLower(u.Hostname())

	// Microsoft ATP Safe Links
	// https://{region}.safelinks.protection.outlook.com/?url={encoded}&data=...
	if strings.HasSuffix(host, ".safelinks.protection.outlook.com") ||
		host == "safelinks.protection.outlook.com" {
		if decoded := u.Query().Get("url"); decoded != "" &&
			(strings.HasPrefix(decoded, "http://") || strings.HasPrefix(decoded, "https://")) {
			return decoded, true
		}
	}

	// Proofpoint URLDefense v2
	// https://urldefense.proofpoint.com/v2/url?u={pp_encoded}&d=...
	if host == "urldefense.proofpoint.com" && strings.HasPrefix(u.Path, "/v2/url") {
		if encoded := u.Query().Get("u"); encoded != "" {
			if decoded := decodeProofpointV2(encoded); decoded != "" {
				return decoded, true
			}
		}
	}

	// Proofpoint URLDefense v3
	// https://urldefense.com/v3/__{url}__;{token}!!{hash}
	if (host == "urldefense.com" || host == "urldefense.proofpoint.com") &&
		strings.HasPrefix(u.Path, "/v3/__") {
		if decoded := decodeProofpointV3(u.Path); decoded != "" {
			return decoded, true
		}
	}

	// Mimecast URL Protection
	// https://{region}.mimecastprotect.com/s/{token}?domain={domain}&p={path_encoded}
	// The actual URL is reconstructed from domain + path params.
	if strings.HasSuffix(host, ".mimecastprotect.com") || host == "mimecastprotect.com" {
		if decoded := decodeMimecast(u); decoded != "" {
			return decoded, true
		}
	}

	return "", false
}

// ppV2HexPair matches a Proofpoint v2 encoded character: hyphen + two hex digits.
var ppV2HexPair = regexp.MustCompile(`-([0-9A-Fa-f]{2})`)

// decodeProofpointV2 decodes a Proofpoint URLDefense v2 encoded URL.
// The encoding replaces '%' with '-' in standard percent-encoding.
// Additionally, lone underscores that are not part of the original URL path
// may represent '/' in older variants; we handle both.
func decodeProofpointV2(encoded string) string {
	// Step 1: Replace -XX pairs with %XX so we get standard percent-encoding.
	decoded := ppV2HexPair.ReplaceAllStringFunc(encoded, func(m string) string {
		return "%" + m[1:]
	})

	// Step 2: URL-decode the result.
	result, err := url.QueryUnescape(decoded)
	if err != nil {
		return ""
	}

	// Basic sanity: must look like a URL.
	if !strings.HasPrefix(result, "http://") && !strings.HasPrefix(result, "https://") {
		// Older Proofpoint v2 variant uses underscores for slashes.
		// Try the underscore-based decoding as a fallback.
		return decodeProofpointV2UnderscoreVariant(encoded)
	}

	return result
}

// decodeProofpointV2UnderscoreVariant handles an older Proofpoint v2 encoding
// where underscores represent path separators throughout the URL.
// The format is "http-3A__host_path" where __ represents "://" and _ represents "/".
func decodeProofpointV2UnderscoreVariant(encoded string) string {
	// First decode -XX hex pairs.
	decoded := ppV2HexPair.ReplaceAllStringFunc(encoded, func(m string) string {
		return "%" + m[1:]
	})
	// URL-decode.
	step2, err := url.QueryUnescape(decoded)
	if err != nil {
		step2 = decoded
	}
	// In the v2 underscore encoding, __ represents :// (scheme separator) and
	// single _ represents / (path separator) throughout the URL.
	result := strings.ReplaceAll(step2, "__", "//")
	result = strings.ReplaceAll(result, "_", "/")

	if strings.HasPrefix(result, "http://") || strings.HasPrefix(result, "https://") {
		return result
	}
	return ""
}

// ppV3Boundary is the regex that finds the end of the embedded URL in a v3 path.
// The URL is between "__" prefix and "__;".
var ppV3Boundary = regexp.MustCompile(`^/v3/__(.+?)__(?:;|$)`)

// ppV3HexPair matches a Proofpoint v3 encoded character: asterisk + two hex digits.
var ppV3HexPair = regexp.MustCompile(`\*([0-9A-Fa-f]{2})`)

// decodeProofpointV3 extracts and decodes the embedded URL from a Proofpoint v3 path.
// v3 format: /v3/__{url}__;{token}!!{hash}
// Special encoding: *XX → %XX (asterisk used instead of percent for encoding).
func decodeProofpointV3(path string) string {
	m := ppV3Boundary.FindStringSubmatch(path)
	if len(m) < 2 {
		return ""
	}
	encoded := m[1]

	// Replace *XX with %XX.
	decoded := ppV3HexPair.ReplaceAllStringFunc(encoded, func(match string) string {
		return "%" + match[1:]
	})

	// URL-decode the result.
	result, err := url.QueryUnescape(decoded)
	if err != nil {
		return ""
	}

	if strings.HasPrefix(result, "http://") || strings.HasPrefix(result, "https://") {
		return result
	}
	return ""
}

// decodeMimecast reconstructs the original URL from a Mimecast URL Protection link.
// Mimecast encodes the URL as: scheme://domain/path in separate query parameters.
// The exact format varies by Mimecast version; we handle the common "domain" + optional
// "p" (encoded path) parameters.
func decodeMimecast(u *url.URL) string {
	q := u.Query()

	domain := q.Get("domain")
	if domain == "" {
		return ""
	}

	// Reconstruct the URL: always HTTPS (Mimecast promotes to HTTPS).
	scheme := "https"
	if q.Get("s") != "" {
		// Some variants carry the scheme in s=0 (http) or s=1 (https).
		if q.Get("s") == "0" {
			scheme = "http"
		}
	}

	path := ""
	if p := q.Get("p"); p != "" {
		// Path is sometimes base64 or percent-encoded.
		if decoded, err := url.QueryUnescape(p); err == nil {
			path = decoded
		} else {
			path = p
		}
	}

	result := scheme + "://" + domain + path
	if strings.HasPrefix(result, "http://") || strings.HasPrefix(result, "https://") {
		return result
	}
	return ""
}
