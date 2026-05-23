package metrics

import "github.com/prometheus/client_golang/prometheus"

var (
	// mailhook_scans_total — total scans by verdict (spec §17)
	ScansTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "mailhook_scans_total",
			Help: "Total scans by verdict.",
		},
		[]string{"verdict"},
	)

	// mailhook_pipeline_duration_seconds — end-to-end scan duration (spec §17)
	PipelineDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "mailhook_pipeline_duration_seconds",
		Help:    "Scan pipeline end-to-end duration in seconds.",
		Buckets: []float64{0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0},
	})

	// mailhook_scanner_duration_seconds — per-scanner latency
	ScannerDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "mailhook_scanner_duration_seconds",
			Help:    "Per-scanner scan duration.",
			Buckets: []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5},
		},
		[]string{"scanner", "verdict"},
	)

	// mailhook_scanner_up — availability per scanner (spec §17)
	ScannerUp = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "mailhook_scanner_up",
			Help: "Scanner availability (1=up, 0=down).",
		},
		[]string{"scanner"},
	)

	// mailhook_quarantine_queue_total — current quarantined email count (spec §17)
	QuarantineQueueTotal = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "mailhook_quarantine_queue_total",
		Help: "Current count of quarantined emails.",
	})

	// mailhook_feed_entries_total — per-feed entry counts (spec §17)
	FeedEntriesTotal = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "mailhook_feed_entries_total",
			Help: "Entries loaded per threat feed.",
		},
		[]string{"feed"},
	)

	// mailhook_yara_rules_total — loaded YARA rule count (spec §17)
	YARARulesTotal = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "mailhook_yara_rules_total",
		Help: "Number of loaded YARA rules.",
	})

	// mailhook_imap_reconnects_total — IMAP reconnection counter (spec §17)
	IMAPReconnectsTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "mailhook_imap_reconnects_total",
		Help: "Total IMAP reconnection attempts.",
	})

	// mailhook_db_size_bytes — SQLite database file size (spec §17)
	DBSizeBytes = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "mailhook_db_size_bytes",
		Help: "SQLite database size in bytes.",
	})

	// mailhook_eml_store_size_bytes — EML storage total size (spec §17)
	EMLStoreSizeBytes = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "mailhook_eml_store_size_bytes",
		Help: "EML store total size in bytes.",
	})

	// mailhook_sse_clients_current — connected SSE clients
	SSEClients = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "mailhook_sse_clients_current",
		Help: "Current number of SSE subscribers.",
	})

	// mailhook_scanner_errors_total — scanner error/timeout count
	ScannerErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "mailhook_scanner_errors_total",
			Help: "Total scanner errors or timeouts by scanner.",
		},
		[]string{"scanner"},
	)
)

func init() {
	prometheus.MustRegister(
		ScansTotal,
		PipelineDuration,
		ScannerDuration,
		ScannerUp,
		QuarantineQueueTotal,
		FeedEntriesTotal,
		YARARulesTotal,
		IMAPReconnectsTotal,
		DBSizeBytes,
		EMLStoreSizeBytes,
		SSEClients,
		ScannerErrors,
	)
}
