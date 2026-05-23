package handlers

import (
	"io"
	"net/http"
	"time"

	"github.com/izm1chael/mailhook/web"
)

// SSEHandler streams real-time scan events to the dashboard.
type SSEHandler struct {
	hub *web.SSEHub
}

// NewSSEHandler creates an SSEHandler.
func NewSSEHandler(hub *web.SSEHub) *SSEHandler {
	return &SSEHandler{hub: hub}
}

// GetEvents handles GET /api/events — the Server-Sent Events endpoint.
func (h *SSEHandler) GetEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // disable nginx proxy buffering
	w.WriteHeader(http.StatusOK)

	ch := h.hub.Subscribe()
	defer h.hub.Unsubscribe(ch)

	// Heartbeat keeps the connection alive through proxies that close idle streams
	heartbeat := time.NewTicker(30 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case data, ok := <-ch:
			if !ok {
				return
			}
			w.Write([]byte("data: "))
			w.Write(data) // nosemgrep: go.lang.security.audit.xss.no-direct-write-to-responsewriter.no-direct-write-to-responsewriter
			w.Write([]byte("\n\n"))
			flusher.Flush()

		case <-heartbeat.C:
			io.WriteString(w, ": heartbeat\n\n")
			flusher.Flush()

		case <-r.Context().Done():
			return
		}
	}
}
