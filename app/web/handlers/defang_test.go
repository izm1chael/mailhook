package handlers

import (
	"testing"

	"github.com/izm1chael/mailhook/util"
)

func TestDefang(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		// Protocol defang
		{"https://evil.com/path", "hxxps://evil[.]com/path"},
		{"http://phishing.example.com/login", "hxxp://phishing[.]example[.]com/login"},
		{"ftp://files.example.com/file.zip", "fxp://files[.]example[.]com/file.zip"},

		// Dots in host only, not path
		{"https://evil.com/path/to/file.txt", "hxxps://evil[.]com/path/to/file.txt"},

		// Multiple dots in host
		{"https://sub.domain.example.com/", "hxxps://sub[.]domain[.]example[.]com/"},

		// Query string — dots in host defanged, rest preserved
		{"https://evil.com/page?foo=bar.baz", "hxxps://evil[.]com/page?foo=bar.baz"},

		// No protocol — all dots replaced
		{"evil.com", "evil[.]com"},

		// Already has no dots in host
		{"https://localhost/api", "hxxps://localhost/api"},
	}

	for _, tc := range cases {
		got := util.DefangURL(tc.in)
		if got != tc.want {
			t.Errorf("DefangURL(%q)\n  got  %q\n  want %q", tc.in, got, tc.want)
		}
	}
}
