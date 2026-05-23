package util

import "strings"

// DefangURL replaces scheme markers and host dots for safe display in reports.
// "https://evil.com/path" → "hxxps://evil[.]com/path"
func DefangURL(rawURL string) string {
	u := strings.NewReplacer(
		"https://", "hxxps://",
		"http://", "hxxp://",
		"ftp://", "fxp://",
	).Replace(rawURL)

	slashIdx := strings.Index(u, "://")
	if slashIdx >= 0 {
		afterProto := slashIdx + 3
		hostEnd := strings.IndexByte(u[afterProto:], '/')
		if hostEnd < 0 {
			host := u[afterProto:]
			return u[:afterProto] + strings.ReplaceAll(host, ".", "[.]")
		}
		host := u[afterProto : afterProto+hostEnd]
		return u[:afterProto] + strings.ReplaceAll(host, ".", "[.]") + u[afterProto+hostEnd:]
	}
	return strings.ReplaceAll(u, ".", "[.]")
}

// DefangIP replaces dots in an IP address with "[.]" for safe display.
func DefangIP(ip string) string {
	return strings.ReplaceAll(ip, ".", "[.]")
}
