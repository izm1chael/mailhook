package handlers

import (
	"net"
	"net/http"

	"github.com/izm1chael/mailhook/auth"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// MetricsHandler serves Prometheus metrics, restricted to allowed CIDRs.
type MetricsHandler struct {
	allowedCIDRs []*net.IPNet
	middleware   *auth.Middleware
	handler      http.Handler
}

// NewMetricsHandler creates a MetricsHandler that only responds to IPs in allowedCIDRs.
// It uses middleware.ClientIP for IP extraction, which respects trusted-proxy configuration.
func NewMetricsHandler(cidrs []string, middleware *auth.Middleware) (*MetricsHandler, error) {
	var nets []*net.IPNet
	for _, cidr := range cidrs {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, err
		}
		nets = append(nets, ipnet)
	}
	return &MetricsHandler{
		allowedCIDRs: nets,
		middleware:   middleware,
		handler:      promhttp.Handler(),
	}, nil
}

// GetMetrics handles GET /metrics.
func (h *MetricsHandler) GetMetrics(w http.ResponseWriter, r *http.Request) {
	ip := h.middleware.ClientIP(r)
	parsed := net.ParseIP(ip)
	if parsed == nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	for _, ipnet := range h.allowedCIDRs {
		if ipnet.Contains(parsed) {
			h.handler.ServeHTTP(w, r)
			return
		}
	}
	http.Error(w, "forbidden", http.StatusForbidden)
}
