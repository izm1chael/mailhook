package feeds

import (
	"context"
	"encoding/csv"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const threatfoxURL = "https://threatfox.abuse.ch/export/csv/recent/"

type threatfoxFeed struct{}

func (threatfoxFeed) Name() string { return "threatfox" }

func (threatfoxFeed) Fetch(ctx context.Context, cacheDir string) ([]string, error) {
	cachePath := filepath.Join(cacheDir, "threatfox.csv")

	raw, err := httpGet(ctx, threatfoxURL, "MailHook/1.0")
	if err != nil {
		// Fall back to local cache — do not use loadCacheFile (its .csv branch calls parseURLhaus)
		cached, readErr := os.ReadFile(cachePath)
		if readErr != nil {
			return nil, readErr
		}
		return parseThreatFox(cached)
	}

	_ = writeFileSafe(cachePath, raw, 0o640) // cache miss is non-fatal
	return parseThreatFox(raw)
}

// parseThreatFox parses the ThreatFox CSV export and returns URL/domain IOCs.
// Rows with ioc_type "url" are returned as-is; "domain" rows are wrapped with
// "http://" so normalizeURL can parse the hostname correctly.
// IOC types "ip:port", "md5_hash", and "sha256_hash" are skipped.
func parseThreatFox(raw []byte) ([]string, error) {
	r := csv.NewReader(strings.NewReader(string(raw)))
	r.Comment = '#'
	r.FieldsPerRecord = -1

	// CSV columns: id, ioc, threat_type, ioc_type, malware, malware_printable, ...
	var iocs []string
	for {
		record, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}
		if len(record) < 4 {
			continue
		}
		iocType := strings.TrimSpace(record[3])
		ioc := strings.TrimSpace(record[1])
		if ioc == "" {
			continue
		}
		switch iocType {
		case "url":
			iocs = append(iocs, ioc)
		case "domain":
			iocs = append(iocs, "http://"+ioc)
		}
	}
	return iocs, nil
}
