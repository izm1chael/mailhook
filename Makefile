BINARY     := bin/mailhook
BINARY_AI  := bin/mailhook-ai
VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
APP_DIR    := app
GOARCH     ?= $(shell go env GOARCH)
NFPM_ARCH  ?= $(GOARCH)

# ONNX Runtime paths (override for non-standard installs)
ONNX_INCLUDE ?= /usr/local/include/onnxruntime
ONNX_LIB     ?= /usr/local/lib

.PHONY: build build-ai test test-ai test-race vet lint docker-build docker-build-ai \
        docker-build-standard up down logs tidy clean \
        package-deb package-rpm package-deb-ai package-rpm-ai \
        models-dl models-bert models-dga bench bench-ai \
        simulate simulate-assert simulate-json setup-password \
        bench-live bench-live-up bench-live-down

build:
	@mkdir -p bin
	cd $(APP_DIR) && CGO_ENABLED=1 go build \
	  -tags yara_static \
	  -trimpath \
	  -ldflags="-s -w -X main.version=$(VERSION)" \
	  -o ../$(BINARY) \
	  .

build-ai:
	@mkdir -p bin
	cd $(APP_DIR) && CGO_ENABLED=1 \
	  CGO_CFLAGS="-I$(ONNX_INCLUDE)" \
	  CGO_LDFLAGS="-L$(ONNX_LIB) -lonnxruntime" \
	  go build \
	  -tags "yara_static ai" \
	  -trimpath \
	  -ldflags="-s -w -X main.version=$(VERSION)" \
	  -o ../$(BINARY_AI) \
	  .

test:
	cd $(APP_DIR) && CGO_ENABLED=1 go test ./... -timeout 60s

test-ai:
	cd $(APP_DIR) && CGO_ENABLED=1 \
	  CGO_CFLAGS="-I$(ONNX_INCLUDE)" \
	  CGO_LDFLAGS="-L$(ONNX_LIB) -lonnxruntime" \
	  go test -tags "yara_static ai" ./... -timeout 120s

test-race:
	cd $(APP_DIR) && CGO_ENABLED=1 go test -race ./... -timeout 120s

test-cover:
	cd $(APP_DIR) && CGO_ENABLED=1 go test ./... -coverprofile=../coverage.out
	go tool cover -html=coverage.out -o coverage.html

bench:
	cd $(APP_DIR) && CGO_ENABLED=1 go test \
	  -tags yara_static \
	  -bench=. -benchmem -run='^$$' \
	  ./... -timeout 120s

bench-ai:
	cd $(APP_DIR) && CGO_ENABLED=1 \
	  CGO_CFLAGS="-I$(ONNX_INCLUDE)" \
	  CGO_LDFLAGS="-L$(ONNX_LIB) -lonnxruntime" \
	  go test -tags "yara_static ai" \
	  -bench=. -benchmem -run='^$$' \
	  ./... -timeout 300s

vet:
	cd $(APP_DIR) && go vet ./...

lint:
	cd $(APP_DIR) && golangci-lint run ./...

tidy:
	cd $(APP_DIR) && go mod tidy

docker-build-standard:
	docker compose build --build-arg VERSION=$(VERSION)

docker-build:
	docker compose build --build-arg VERSION=$(VERSION)

docker-build-ai:
	docker compose -f docker-compose.yml -f docker-compose.ai.yml build --build-arg VERSION=$(VERSION)

up:
	docker compose up -d

down:
	docker compose down

logs:
	docker compose logs -f mailhook

# Download / refresh the Tranco Top-10k greylist used by the DGA scanner.
# Files are embedded in the binary by //go:embed — run before 'make build-ai'.
models-dl:
	mkdir -p $(APP_DIR)/scanners/models
	curl -fsSL "https://tranco-list.eu/top-1m.csv.zip" | \
	  zcat | head -10000 | cut -d',' -f2 > $(APP_DIR)/scanners/models/tranco-top10k.txt
	@echo "Tranco greylist updated: $$(wc -l < $(APP_DIR)/scanners/models/tranco-top10k.txt) domains"

# Export DGA CNN model to ONNX (requires Python + torch + huggingface_hub).
# Downloads Reynier/dga-cnn weights from HuggingFace and exports to ONNX.
# Files are embedded in the binary — run before 'make build-ai'.
models-dga:
	pip install --quiet torch huggingface_hub
	python3 scripts/export_dga_onnx.py --outdir $(APP_DIR)/scanners/models/dga-cnn

# Export DistilBERT phishing model to ONNX (requires Python + optimum[onnxruntime]).
# Files are embedded in the binary — run before 'make build-ai'.
models-bert:
	pip install --quiet "optimum[onnxruntime]" transformers onnx
	mkdir -p $(APP_DIR)/scanners/models/distilbert-phishing
	optimum-cli export onnx \
	  --model cybersectony/phishing-email-detection-distilbert_v2.4.1 \
	  --task text-classification \
	  --opset 14 \
	  $(APP_DIR)/scanners/models/distilbert-phishing/
	@echo "DistilBERT exported to $(APP_DIR)/scanners/models/distilbert-phishing/"
	@python3 -c "import onnx; m=onnx.load('$(APP_DIR)/scanners/models/distilbert-phishing/model.onnx'); \
	  print('inputs: ', [i.name for i in m.graph.input]); \
	  print('outputs:', [o.name for o in m.graph.output])"

# Run the verdict comparison simulation (no model files required).
simulate:
	cd $(APP_DIR) && CGO_ENABLED=1 go run ./cmd/simulate/

simulate-assert:
	cd $(APP_DIR) && CGO_ENABLED=1 go run ./cmd/simulate/ -assert

simulate-json:
	cd $(APP_DIR) && CGO_ENABLED=1 go run ./cmd/simulate/ -format json

clean:
	rm -rf bin/ dist/ coverage.out coverage.html

package-deb: build
	mkdir -p dist
	BINARY_PATH=$(BINARY) VERSION=$(VERSION) NFPM_ARCH=$(NFPM_ARCH) \
	  nfpm package --config packaging/nfpm.yaml --packager deb --target dist/

package-rpm: build
	mkdir -p dist
	BINARY_PATH=$(BINARY) VERSION=$(VERSION) NFPM_ARCH=$(NFPM_ARCH) \
	  nfpm package --config packaging/nfpm.yaml --packager rpm --target dist/

package-deb-ai: build-ai
	mkdir -p dist
	BINARY_PATH=$(BINARY_AI) VERSION=$(VERSION) NFPM_ARCH=$(NFPM_ARCH) \
	  nfpm package --config packaging/nfpm-ai.yaml --packager deb --target dist/

package-rpm-ai: build-ai
	mkdir -p dist
	BINARY_PATH=$(BINARY_AI) VERSION=$(VERSION) NFPM_ARCH=$(NFPM_ARCH) \
	  nfpm package --config packaging/nfpm-ai.yaml --packager rpm --target dist/

# ─── Live bench (requires docker-compose.bench.yml to be running) ────────────
# Start stack:   make bench-live-up
# Run bench:     make bench-live           (50 random scenarios)
# Run more:      make bench-live N=200 SEED=42
# Stop stack:    make bench-live-down

BENCH_N    ?= 50
BENCH_SEED ?= 0
BENCH_STD  ?= http://localhost:8080
BENCH_AI   ?= http://localhost:8081

bench-live:
	cd $(APP_DIR) && CGO_ENABLED=1 go run ./cmd/bench/ \
	  -std  $(BENCH_STD) \
	  -ai   $(BENCH_AI) \
	  -n    $(BENCH_N) \
	  -seed $(BENCH_SEED)

bench-live-up:
	docker compose -f docker-compose.bench.yml up -d --build

bench-live-down:
	docker compose -f docker-compose.bench.yml down

setup-password:
	@read -s -p "Enter UI password: " pw; echo; \
	python3 -c "import crypt; print(crypt.crypt('$$pw', crypt.mksalt(crypt.METHOD_BLOWFISH)))" 2>/dev/null || \
	docker run --rm golang:1.23-alpine sh -c \
	  "apk add -q apache2-utils && htpasswd -nbB -C 12 user '$$pw' | cut -d: -f2"
