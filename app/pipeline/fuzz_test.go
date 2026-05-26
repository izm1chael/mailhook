package pipeline

import (
	"os"
	"testing"
)

// FuzzParse fuzzes the main RFC822 email parser — the primary untrusted-input entry
// point for every email that flows through the gateway.
func FuzzParse(f *testing.F) {
	for _, name := range []string{
		"../testdata/eml/simple.eml",
		"../testdata/eml/html_with_urls.eml",
		"../testdata/eml/html_smuggling.eml",
		"../testdata/eml/auth_fail.eml",
		"../testdata/eml/hidden_text.eml",
	} {
		raw, err := readFile(name)
		if err == nil {
			f.Add(raw)
		}
	}

	// Minimal valid RFC822 seed so the fuzzer has a parseable starting point.
	f.Add([]byte("From: a@b.com\r\nTo: c@d.com\r\nSubject: test\r\n\r\nbody\r\n"))

	f.Fuzz(func(t *testing.T, raw []byte) {
		// Must not panic regardless of input; errors are expected and fine.
		//nolint:errcheck
		Parse(raw, "fuzz", 1, "INBOX", 1*1024*1024, "")
	})
}

// FuzzDecodeSafeLink fuzzes all four safe-link URL decoders (Microsoft ATP,
// Proofpoint v2/v3, Mimecast) — they process attacker-controlled URL data.
func FuzzDecodeSafeLink(f *testing.F) {
	f.Add("https://nam.safelinks.protection.outlook.com/?url=https%3A%2F%2Fevil.com&data=x")
	f.Add("https://urldefense.proofpoint.com/v2/url?u=http-3A__evil.com&d=x")
	f.Add("https://urldefense.com/v3/__https://evil.com__;!!x")
	f.Add("https://eu1.mimecastprotect.com/s/tok?domain=evil.com&p=%2Fpath")
	f.Add("https://example.com/not-a-safe-link")
	f.Add("")

	f.Fuzz(func(t *testing.T, rawURL string) {
		decodeSafeLink(rawURL)
	})
}

// FuzzNormalizeURL fuzzes URL normalisation which strips tracking params and
// lowercases scheme/host — inputs come from untrusted email body content.
func FuzzNormalizeURL(f *testing.F) {
	f.Add("https://Example.COM/path?utm_source=x&q=keep")
	f.Add("http://foo.bar/a/b/c")
	f.Add("not-a-url")
	f.Add("")
	f.Add("https://x.com/path?a=1&utm_medium=email&b=2")

	f.Fuzz(func(t *testing.T, raw string) {
		normalizeURL(raw)
	})
}

// readFile reads a file for use as a seed corpus entry.
func readFile(name string) ([]byte, error) {
	return os.ReadFile(name)
}
