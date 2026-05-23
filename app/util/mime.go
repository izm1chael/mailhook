package util

import (
	"mime"
	"path/filepath"
	"strings"
)

// dangerousExtensions is the set of file extensions that are considered high-risk
// regardless of Content-Type. This list mirrors the spec's DANGEROUS_EXTENSIONS env var.
var dangerousExtensions = map[string]bool{
	// Classic executable / script types
	".exe": true, ".bat": true, ".cmd": true, ".ps1": true,
	".vbs": true, ".vbe": true, ".js": true, ".jse": true,
	".wsf": true, ".wsh": true, ".lnk": true, ".scr": true,
	".pif": true, ".com": true, ".hta": true, ".msi": true,
	".reg": true, ".jar": true, ".msp": true, ".mst": true,
	".cpl": true, ".inf": true, ".sys": true, ".dll": true,
	// Launcher / shell types
	".scf": true, ".url": true, ".jnlp": true, ".msc": true, ".ps2": true,
	// Disk-image containers (bypass Mark-of-the-Web on Windows)
	".iso": true, ".img": true, ".vhd": true, ".vhdx": true,
	// OneNote (heavily abused for malware delivery)
	".one": true,
	// Macro-enabled Office formats
	".docm": true, ".xlsm": true, ".pptm": true, ".dotm": true,
}

// executableMIMETypes is the set of MIME types associated with executable content.
var executableMIMETypes = map[string]bool{
	"application/x-msdownload":                true,
	"application/x-executable":                true,
	"application/x-msdos-program":             true,
	"application/x-ms-installer":              true,
	"application/vnd.microsoft.portable-executable": true,
	"application/x-dosexec":                   true,
	"application/x-sh":                        true,
	"application/x-bat":                       true,
	"application/x-jar":                       true,
}

// DangerousExtension reports whether filename has a dangerous extension.
func DangerousExtension(filename string) bool {
	ext := strings.ToLower(filepath.Ext(filename))
	return dangerousExtensions[ext]
}

// IsExecutable reports whether the given MIME type is associated with executable content.
func IsExecutable(contentType string) bool {
	mt, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return false
	}
	return executableMIMETypes[strings.ToLower(mt)]
}

// SafeContentType returns the MIME type without parameters (safe for logging).
func SafeContentType(contentType string) string {
	mt, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return contentType
	}
	return mt
}

// TruncateString returns s truncated to max runes, appending "…" if truncated.
func TruncateString(s string, max int) string {
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	return string(runes[:max]) + "…"
}
