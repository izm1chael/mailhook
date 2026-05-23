package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/izm1chael/mailhook/auth"
	"github.com/izm1chael/mailhook/config"
	"github.com/izm1chael/mailhook/pipeline"
)

// ScanHandler handles POST /api/scan — an IP-restricted endpoint for live benchmarking.
// Accepts raw EML in the request body, runs all configured scanners, returns JSON verdict.
// Access is gated by the same CIDR list as /metrics (MAILHOOK_METRICS_ALLOWED_CIDRS).
type ScanHandler struct {
	run          func(context.Context, []byte) (pipeline.VerdictDecision, []pipeline.ScanResult, time.Duration, error)
	allowedCIDRs []*net.IPNet
	middleware   *auth.Middleware
}

// NewScanHandler creates a ScanHandler. Returns nil if no CIDRs are configured
// (the endpoint is disabled and main.go should not register the route).
func NewScanHandler(
	scanners []pipeline.Scanner,
	cfg *config.Config,
	cidrs []string,
	middleware *auth.Middleware,
) (*ScanHandler, error) {
	var nets []*net.IPNet
	for _, cidr := range cidrs {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, err
		}
		nets = append(nets, ipnet)
	}
	return &ScanHandler{
		run: func(ctx context.Context, raw []byte) (pipeline.VerdictDecision, []pipeline.ScanResult, time.Duration, error) {
			return pipeline.RunScan(ctx, scanners, cfg, raw)
		},
		allowedCIDRs: nets,
		middleware:   middleware,
	}, nil
}

type scanResponse struct {
	Verdict    string                `json:"verdict"`
	Decision   string                `json:"decision"`
	Reason     string                `json:"reason"`
	Confidence float64               `json:"confidence"`
	ElapsedMs  int64                 `json:"elapsed_ms"`
	Scanners   []pipeline.ScanResult `json:"scanners"`
}

// PostScan handles POST /api/scan.
func (h *ScanHandler) PostScan(w http.ResponseWriter, r *http.Request) {
	ip := h.middleware.ClientIP(r)
	parsed := net.ParseIP(ip)
	allowed := false
	if parsed != nil {
		for _, ipnet := range h.allowedCIDRs {
			if ipnet.Contains(parsed) {
				allowed = true
				break
			}
		}
	}
	if !allowed {
		http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 25*1024*1024)
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			http.Error(w, `{"error":"email too large (25 MB limit)"}`, http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, `{"error":"body required"}`, http.StatusBadRequest)
		return
	}
	if len(raw) == 0 {
		http.Error(w, `{"error":"body required"}`, http.StatusBadRequest)
		return
	}

	vd, results, elapsed, err := h.run(r.Context(), raw)
	if err != nil {
		http.Error(w, `{"error":"parse failed: `+err.Error()+`"}`, http.StatusUnprocessableEntity)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scanResponse{ //nolint:errcheck
		Verdict:    vd.Verdict,
		Decision:   vd.Decision,
		Reason:     vd.Reason,
		Confidence: vd.Confidence,
		ElapsedMs:  elapsed.Milliseconds(),
		Scanners:   results,
	})
}
