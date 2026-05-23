# Builder: Debian 12 (bookworm) — same glibc as runtime image.
# Debian 12 ships libyara 4.2.3; go-yara v4 needs >= 4.3, so we compile YARA from source.
FROM golang:1.26.3-bookworm@sha256:386d475a660466863d9f8c766fec64d7fdad3edac2c6a05020c09534d71edb4b AS builder

ARG YARA_VERSION=4.5.2

RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends \
        gcc \
        make \
        automake \
        autoconf \
        libtool \
        libssl-dev \
        libmagic-dev \
        libjansson-dev \
        pkg-config \
        ca-certificates \
        wget \
    && rm -rf /var/lib/apt/lists/*

# Compile YARA from source (Debian 12 repo only has 4.2.3).
RUN set -eux; \
    cd /tmp; \
    wget -qO yara.tar.gz \
      "https://github.com/VirusTotal/yara/archive/refs/tags/v${YARA_VERSION}.tar.gz"; \
    tar -xzf yara.tar.gz; \
    cd "yara-${YARA_VERSION}"; \
    autoreconf -fiv; \
    ./configure \
        --enable-magic \
        --with-crypto \
        --disable-shared \
        --enable-static \
        --prefix=/usr/local; \
    make -j"$(nproc)"; \
    make install; \
    rm -rf /tmp/yara*

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

ARG VERSION=dev
# yara_static links libyara.a; runtime needs libmagic + libssl (shared).
RUN PKG_CONFIG_PATH=/usr/local/lib/pkgconfig \
    CGO_ENABLED=1 GOOS=linux go build \
    -tags yara_static \
    -trimpath \
    "-ldflags=-s -w -X main.version=${VERSION}" \
    -o /out/mailhook \
    .

# ── Runtime: debian:12-slim (~75MB, same glibc, minimal packages) ─────────────
FROM debian:12-slim@sha256:0104b334637a5f19aa9c983a91b54c89887c0984081f2068983107a6f6c21eeb

RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends \
        libmagic1 \
        libssl3 \
        ca-certificates \
        tzdata \
        wget \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r -g 1000 mailhook \
    && useradd -r -u 1000 -g mailhook --no-create-home --shell /usr/sbin/nologin mailhook \
    && install -d -o mailhook -g mailhook -m 750 \
        /data /data/emls \
        /feeds-cache \
        /rules

COPY --from=builder /out/mailhook /usr/local/bin/mailhook

VOLUME ["/data", "/feeds-cache", "/rules"]

USER mailhook
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD wget -qO- http://localhost:8080/healthz || exit 1

ENTRYPOINT ["/usr/local/bin/mailhook"]
