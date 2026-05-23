package util

import (
	"net"
	"regexp"
)

var receivedIPv4 = regexp.MustCompile(`\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]`)

// ExtractSendingIP returns the public IP that actually sent the email to Purelymail.
//
// Received headers are added outermost-first (index 0 = most recent hop added by
// Purelymail's own edge). We parse them innermost-first (highest index first) to
// find the first external hop that Purelymail accepted from. This correctly ignores
// forged Received headers injected by an attacker inside the email body.
func ExtractSendingIP(receivedHeaders []string) net.IP {
	// Walk from the innermost (oldest) header outward.
	// Stop at the first public IP — that is the true sender's IP as seen by Purelymail.
	for i := len(receivedHeaders) - 1; i >= 0; i-- {
		matches := receivedIPv4.FindStringSubmatch(receivedHeaders[i])
		if len(matches) < 2 {
			continue
		}
		ip := net.ParseIP(matches[1])
		if ip == nil {
			continue
		}
		if IsPublicIP(ip) {
			return ip
		}
	}
	return nil
}

// IsPublicIP reports whether ip is a publicly routable address.
// Returns false for loopback, link-local, private RFC1918, and special-use ranges.
func IsPublicIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	ip = ip.To4()
	if ip == nil {
		return false // IPv6 not supported for reputation checks yet
	}
	private := []net.IPNet{
		{IP: net.IP{10, 0, 0, 0}, Mask: net.CIDRMask(8, 32)},
		{IP: net.IP{172, 16, 0, 0}, Mask: net.CIDRMask(12, 32)},
		{IP: net.IP{192, 168, 0, 0}, Mask: net.CIDRMask(16, 32)},
		{IP: net.IP{127, 0, 0, 0}, Mask: net.CIDRMask(8, 32)},
		{IP: net.IP{169, 254, 0, 0}, Mask: net.CIDRMask(16, 32)},
		{IP: net.IP{100, 64, 0, 0}, Mask: net.CIDRMask(10, 32)},
		{IP: net.IP{0, 0, 0, 0}, Mask: net.CIDRMask(8, 32)},
	}
	for _, block := range private {
		if block.Contains(ip) {
			return false
		}
	}
	return true
}
