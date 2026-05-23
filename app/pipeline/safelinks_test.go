package pipeline

import (
	"testing"
)

func TestDecodeSafeLink_MicrosoftATP(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "nam12 region",
			input: "https://nam12.safelinks.protection.outlook.com/?url=https%3A%2F%2Fevil.com%2Fpayload&data=05%7C01%7C%7Cabc123&sdata=xyz&reserved=0",
			want:  "https://evil.com/payload",
		},
		{
			name:  "eur01 region",
			input: "https://eur01.safelinks.protection.outlook.com/?url=http%3A%2F%2Fphish.example.org%2Fsteal%3Ftoken%3Dabc&data=something",
			want:  "http://phish.example.org/steal?token=abc",
		},
		{
			name:  "apex domain (no region prefix)",
			input: "https://safelinks.protection.outlook.com/?url=https%3A%2F%2Fmalware.site%2F&data=x",
			want:  "https://malware.site/",
		},
		{
			name:  "no url param → not decoded",
			input: "https://nam12.safelinks.protection.outlook.com/?data=something",
			want:  "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := decodeSafeLink(tc.input)
			if tc.want == "" {
				if ok {
					t.Errorf("expected no decode, got %q", got)
				}
			} else {
				if !ok {
					t.Fatalf("expected decode ok=true, got false")
				}
				if got != tc.want {
					t.Errorf("want %q, got %q", tc.want, got)
				}
			}
		})
	}
}

func TestDecodeSafeLink_ProofpointV2(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "basic http URL",
			input: "https://urldefense.proofpoint.com/v2/url?u=http-3A__www-2Eevil-2Ecom_payload&d=DwMF-g&c=something&r=abc&m=xyz&s=sig&e=",
			want:  "http://www.evil.com/payload",
		},
		{
			name:  "https with path",
			input: "https://urldefense.proofpoint.com/v2/url?u=https-3A__phish-2Eexample-2Eorg_steal-3Ftoken-3Dabc&d=x",
			want:  "https://phish.example.org/steal?token=abc",
		},
		{
			name:  "no u param → not decoded",
			input: "https://urldefense.proofpoint.com/v2/url?d=something&m=xyz",
			want:  "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := decodeSafeLink(tc.input)
			if tc.want == "" {
				if ok {
					t.Errorf("expected no decode, got %q", got)
				}
			} else {
				if !ok {
					t.Fatalf("expected decode ok=true, got false for %q", tc.input)
				}
				if got != tc.want {
					t.Errorf("want %q, got %q", tc.want, got)
				}
			}
		})
	}
}

func TestDecodeSafeLink_ProofpointV3(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "basic https URL",
			input: "https://urldefense.com/v3/__https://evil.com/payload__;!!abc123",
			want:  "https://evil.com/payload",
		},
		{
			name:  "URL with encoded comma",
			input: "https://urldefense.com/v3/__https://evil.com/path*2Cwith*2Ccommas__;!!xyz",
			want:  "https://evil.com/path,with,commas",
		},
		{
			name:  "URL with query string",
			input: "https://urldefense.com/v3/__https://phish.example.org/steal*3Ftoken*3Dabc__;!!hash!!",
			want:  "https://phish.example.org/steal?token=abc",
		},
		{
			name:  "proofpoint.com v3 host",
			input: "https://urldefense.proofpoint.com/v3/__https://malware.site/__;!!sig",
			want:  "https://malware.site/",
		},
		{
			name:  "no v3 boundary → not decoded",
			input: "https://urldefense.com/v3/other",
			want:  "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := decodeSafeLink(tc.input)
			if tc.want == "" {
				if ok {
					t.Errorf("expected no decode, got %q", got)
				}
			} else {
				if !ok {
					t.Fatalf("expected decode ok=true, got false for %q", tc.input)
				}
				if got != tc.want {
					t.Errorf("want %q, got %q", tc.want, got)
				}
			}
		})
	}
}

func TestDecodeSafeLink_Mimecast(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "basic domain + path",
			input: "https://url.au.m.mimecastprotect.com/s/abc123?domain=evil.com&p=%2Fpayload",
			want:  "https://evil.com/payload",
		},
		{
			name:  "domain only, no path",
			input: "https://url.au.m.mimecastprotect.com/s/xyz?domain=phish.example.org",
			want:  "https://phish.example.org",
		},
		{
			name:  "no domain param → not decoded",
			input: "https://url.au.m.mimecastprotect.com/s/abc?token=xyz",
			want:  "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := decodeSafeLink(tc.input)
			if tc.want == "" {
				if ok {
					t.Errorf("expected no decode, got %q", got)
				}
			} else {
				if !ok {
					t.Fatalf("expected decode ok=true, got false for %q", tc.input)
				}
				if got != tc.want {
					t.Errorf("want %q, got %q", tc.want, got)
				}
			}
		})
	}
}

func TestDecodeSafeLink_NotAWrapper(t *testing.T) {
	cases := []string{
		"https://evil.com/direct",
		"https://example.com/page?url=something",
		"http://google.com",
		"not-a-url",
	}
	for _, input := range cases {
		_, ok := decodeSafeLink(input)
		if ok {
			t.Errorf("expected no decode for %q, got ok=true", input)
		}
	}
}

func TestDecodeProofpointV2_HexPairs(t *testing.T) {
	cases := []struct {
		encoded string
		want    string
	}{
		{"http-3A__www-2Eexample-2Ecom", "http://www.example.com"},
		{"https-3A__evil-2Esite_steal", "https://evil.site/steal"},
	}
	for _, tc := range cases {
		got := decodeProofpointV2(tc.encoded)
		if got != tc.want {
			t.Errorf("decodeProofpointV2(%q) = %q, want %q", tc.encoded, got, tc.want)
		}
	}
}

func TestDecodeProofpointV3_StarEncoding(t *testing.T) {
	// *XX decoding: *40 = @, *2F = /, *3A = :
	cases := []struct {
		path string
		want string
	}{
		{"/v3/__https://user*40domain.com/path__;!!", "https://user@domain.com/path"},
		{"/v3/__https://example.com/page*3Fkey*3Dval__;!!", "https://example.com/page?key=val"},
	}
	for _, tc := range cases {
		got := decodeProofpointV3(tc.path)
		if got != tc.want {
			t.Errorf("decodeProofpointV3(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}

func TestExtractURLs_DecodesWrappedURLs(t *testing.T) {
	// Safe Links wrapped URL in HTML href — both the wrapper and real URL should be in the list.
	atpURL := "https://nam12.safelinks.protection.outlook.com/?url=https%3A%2F%2Fevil.com%2Fpayload&data=abc"
	htmlBody := `<a href="` + atpURL + `">click</a>`

	urls := extractURLs("", htmlBody)

	hasATP, hasReal := false, false
	for _, u := range urls {
		if u == "https://nam12.safelinks.protection.outlook.com/?url=https%3a%2f%2fevil.com%2fpayload&data=abc" ||
			u == atpURL {
			hasATP = true
		}
		if u == "https://evil.com/payload" {
			hasReal = true
		}
	}
	if !hasATP {
		t.Error("expected the Safe Links wrapper URL to be in the list")
	}
	if !hasReal {
		t.Errorf("expected the decoded real URL to be in the list; got: %v", urls)
	}
}

func TestExtractURLs_ProofpointWrappedURL(t *testing.T) {
	ppURL := "https://urldefense.proofpoint.com/v2/url?u=https-3A__phish-2Eexample-2Eorg_steal&d=x"
	text := "Check out: " + ppURL

	urls := extractURLs(text, "")

	hasReal := false
	for _, u := range urls {
		if u == "https://phish.example.org/steal" {
			hasReal = true
		}
	}
	if !hasReal {
		t.Errorf("expected decoded Proofpoint URL; got: %v", urls)
	}
}

func TestExtractURLs_NoDuplicateWhenSameURL(t *testing.T) {
	// If the decoded URL is already in the email (not wrapped), don't add it twice.
	realURL := "https://evil.com/payload"
	atpURL := "https://nam12.safelinks.protection.outlook.com/?url=https%3A%2F%2Fevil.com%2Fpayload&data=abc"
	text := realURL + " " + atpURL

	urls := extractURLs(text, "")

	count := 0
	for _, u := range urls {
		if u == "https://evil.com/payload" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected real URL exactly once, got %d times in %v", count, urls)
	}
}
