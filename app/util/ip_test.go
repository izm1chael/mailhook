package util

import (
	"net"
	"testing"
)

func TestIsPublicIP(t *testing.T) {
	cases := []struct {
		ip     string
		public bool
	}{
		// Public IPs
		{"1.1.1.1", true},
		{"8.8.8.8", true},
		{"203.0.113.1", true},
		{"45.33.32.156", true},
		// Private / special
		{"10.0.0.1", false},
		{"10.255.255.255", false},
		{"172.16.0.1", false},
		{"172.31.255.255", false},
		{"192.168.0.1", false},
		{"192.168.255.255", false},
		{"127.0.0.1", false},
		{"127.0.0.0", false},
		{"169.254.0.1", false},
		{"100.64.0.1", false},
		{"0.0.0.0", false},
	}

	for _, tc := range cases {
		ip := net.ParseIP(tc.ip)
		got := IsPublicIP(ip)
		if got != tc.public {
			t.Errorf("IsPublicIP(%s) = %v, want %v", tc.ip, got, tc.public)
		}
	}
}

func TestIsPublicIP_Nil(t *testing.T) {
	if IsPublicIP(nil) {
		t.Error("IsPublicIP(nil) should return false")
	}
}

func TestExtractSendingIP_SingleHop(t *testing.T) {
	headers := []string{
		"from mail.example.com ([203.0.113.1]) by mx.mailhook.test with ESMTP",
	}
	ip := ExtractSendingIP(headers)
	if ip == nil {
		t.Fatal("expected IP, got nil")
	}
	if !ip.Equal(net.ParseIP("203.0.113.1")) {
		t.Errorf("got %v, want 203.0.113.1", ip)
	}
}

func TestExtractSendingIP_MultiHop_InnerMostFirst(t *testing.T) {
	// Header slice: index 0 = most recent (added by our MX), index N = oldest
	// The true sender is the innermost (highest index) public IP
	headers := []string{
		// Our MX (most recent): added after delivery
		"from mx.mailhook.test ([127.0.0.1]) by internal.mailhook.test",
		// Relay (middle)
		"from relay.example.com ([198.51.100.99]) by mx.mailhook.test",
		// True sender (oldest, innermost)
		"from smtp.attacker.example ([45.33.32.156]) by relay.example.com",
	}
	ip := ExtractSendingIP(headers)
	if ip == nil {
		t.Fatal("expected IP, got nil")
	}
	// Should return the innermost public IP (attacker's)
	if !ip.Equal(net.ParseIP("45.33.32.156")) {
		t.Errorf("got %v, want 45.33.32.156 (innermost public IP)", ip)
	}
}

func TestExtractSendingIP_SkipsPrivate(t *testing.T) {
	headers := []string{
		"from localhost ([127.0.0.1]) by internal.test",
		"from internal ([192.168.1.1]) by internal.test",
	}
	ip := ExtractSendingIP(headers)
	if ip != nil {
		t.Errorf("expected nil for all-private headers, got %v", ip)
	}
}

func TestExtractSendingIP_Empty(t *testing.T) {
	ip := ExtractSendingIP(nil)
	if ip != nil {
		t.Errorf("expected nil for empty headers, got %v", ip)
	}
}

func TestExtractSendingIP_NoIPInHeader(t *testing.T) {
	headers := []string{
		"from mail.example.com by mx.mailhook.test",
	}
	ip := ExtractSendingIP(headers)
	if ip != nil {
		t.Errorf("expected nil when no IP brackets, got %v", ip)
	}
}
