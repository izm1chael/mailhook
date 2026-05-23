package scanners

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/izm1chael/mailhook/pipeline"
)

// ClamAV scans email content via the clamd TCP INSTREAM protocol.
// No shell exec, no clamdscan binary required in the MailHook container.
type ClamAV struct {
	mu      sync.RWMutex
	enabled bool
	addr    string // e.g. "clamav:3310"
	timeout time.Duration
	log     *slog.Logger
}

// NewClamAV creates a ClamAV scanner connecting to addr (host:port).
func NewClamAV(addr string, log *slog.Logger) *ClamAV {
	return &ClamAV{enabled: true, addr: addr, timeout: 30 * time.Second, log: log}
}

func (c *ClamAV) Name() string { return "clamav" }

// SetEnabled enables or disables the scanner at runtime.
func (c *ClamAV) SetEnabled(v bool) { c.mu.Lock(); c.enabled = v; c.mu.Unlock() }

// SetAddr changes the ClamAV daemon address at runtime.
func (c *ClamAV) SetAddr(addr string) { c.mu.Lock(); c.addr = addr; c.mu.Unlock() }

// IsEnabled reports whether the scanner is currently enabled.
func (c *ClamAV) IsEnabled() bool { c.mu.RLock(); defer c.mu.RUnlock(); return c.enabled }

// Scan submits the full raw EML and each attachment individually to clamd.
// Returns malicious if any scan finds a signature.
func (c *ClamAV) Scan(ctx context.Context, email *pipeline.Email) pipeline.ScanResult {
	c.mu.RLock()
	enabled := c.enabled
	c.mu.RUnlock()
	if !enabled {
		return pipeline.ScanResult{Scanner: c.Name(), Verdict: "skip", Detail: "disabled"}
	}

	// Scan the full raw message
	result, err := c.scanBytes(ctx, email.Raw)
	if err != nil {
		c.log.Warn("clamd unavailable", "err", err)
		// "error" triggers fail-closed quarantine in verdict.go; "skip" is reserved for disabled-only.
		return pipeline.ScanResult{Scanner: c.Name(), Verdict: "error", Detail: "clamd unavailable: " + err.Error()}
	}
	if result != "" {
		return pipeline.ScanResult{Scanner: c.Name(), Verdict: "malicious",
			Detail: fmt.Sprintf("VIRUS:%s", result)}
	}

	// Scan each attachment individually for higher signal quality
	for _, att := range email.Attachments {
		if len(att.Raw) == 0 {
			continue
		}
		hit, err := c.scanBytes(ctx, att.Raw)
		if err != nil {
			c.log.Warn("clamd attachment scan failed", "filename", att.Filename, "err", err)
			continue
		}
		if hit != "" {
			return pipeline.ScanResult{Scanner: c.Name(), Verdict: "malicious",
				Detail: fmt.Sprintf("VIRUS:%s in %s", hit, att.Filename)}
		}
	}

	return pipeline.ScanResult{Scanner: c.Name(), Verdict: "clean", Detail: "CLEAN"}
}

// Ping sends a PING command to clamd and verifies the PONG response.
func (c *ClamAV) Ping(ctx context.Context) error {
	conn, err := c.dial(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	if _, err := fmt.Fprint(conn, "zPING\x00"); err != nil {
		return fmt.Errorf("write PING: %w", err)
	}
	resp, err := bufio.NewReader(conn).ReadString('\x00')
	if err != nil {
		return fmt.Errorf("read PONG: %w", err)
	}
	if !strings.Contains(resp, "PONG") {
		return fmt.Errorf("unexpected clamd response: %q", resp)
	}
	return nil
}

// scanBytes streams data to clamd using the INSTREAM protocol and returns the
// virus name if found, or empty string if clean.
func (c *ClamAV) scanBytes(ctx context.Context, data []byte) (string, error) {
	conn, err := c.dial(ctx)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	// zINSTREAM\0: null-terminated session mode
	if _, err := fmt.Fprint(conn, "zINSTREAM\x00"); err != nil {
		return "", fmt.Errorf("write INSTREAM: %w", err)
	}

	// Stream data in 2KB chunks: [4-byte big-endian length][data]
	const chunkSize = 2048
	for i := 0; i < len(data); i += chunkSize {
		end := i + chunkSize
		if end > len(data) {
			end = len(data)
		}
		chunk := data[i:end]
		if err := binary.Write(conn, binary.BigEndian, uint32(len(chunk))); err != nil {
			return "", fmt.Errorf("write chunk len: %w", err)
		}
		if _, err := conn.Write(chunk); err != nil {
			return "", fmt.Errorf("write chunk: %w", err)
		}
	}

	// Terminate stream with 4-byte zero
	if err := binary.Write(conn, binary.BigEndian, uint32(0)); err != nil {
		return "", fmt.Errorf("write stream terminator: %w", err)
	}

	// Read response: "stream: OK\x00" or "stream: VirusName FOUND\x00" (z-protocol = NUL-terminated)
	resp, err := bufio.NewReader(conn).ReadString('\x00')
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}

	resp = strings.TrimRight(strings.TrimSpace(resp), "\x00")
	if resp == "stream: OK" {
		return "", nil
	}
	if strings.HasSuffix(resp, " FOUND") {
		// Extract signature name: "stream: EICAR-Test-Signature FOUND"
		parts := strings.SplitN(resp, ": ", 2)
		if len(parts) == 2 {
			sig := strings.TrimSuffix(parts[1], " FOUND")
			return sig, nil
		}
	}

	// Unexpected response — treat as error but not a virus hit
	return "", fmt.Errorf("unexpected clamd response: %q", resp)
}

func (c *ClamAV) dial(ctx context.Context) (net.Conn, error) {
	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", c.addr)
	if err != nil {
		return nil, fmt.Errorf("connect clamd %s: %w", c.addr, err)
	}
	conn.SetDeadline(time.Now().Add(c.timeout)) //nolint:errcheck
	return conn, nil
}

