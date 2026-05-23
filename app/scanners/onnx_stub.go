//go:build !ai

package scanners

import (
	"context"
	"log/slog"

	"github.com/izm1chael/mailhook/config"
	"github.com/izm1chael/mailhook/pipeline"
)

// ONNXScanner is a no-op stub compiled when the 'ai' build tag is absent.
// It satisfies the pipeline.Scanner interface so main.go can unconditionally
// include it in the scanner slice.
type ONNXScanner struct{}

func NewONNXScanner(_ *config.Config, _ *slog.Logger) (*ONNXScanner, error) {
	return &ONNXScanner{}, nil
}

func (o *ONNXScanner) Name() string { return "onnx" }

func (o *ONNXScanner) Scan(_ context.Context, _ *pipeline.Email) pipeline.ScanResult {
	return pipeline.ScanResult{Scanner: "onnx", Verdict: "skip", Detail: "ai build tag not set"}
}

func (o *ONNXScanner) Close() {}

func (o *ONNXScanner) SetEnabled(_ bool) {}

func (o *ONNXScanner) IsEnabled() bool { return false }
