# MailHook

[![CI](https://github.com/izm1chael/mailhook/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/izm1chael/mailhook/actions/workflows/ci.yml)
[![Release](https://github.com/izm1chael/mailhook/actions/workflows/release.yml/badge.svg)](https://github.com/izm1chael/mailhook/actions/workflows/release.yml)
[![Latest Release](https://img.shields.io/github/v/release/izm1chael/mailhook?logo=github&label=release)](https://github.com/izm1chael/mailhook/releases/latest)
[![Container](https://img.shields.io/badge/ghcr.io-mailhook-blue?logo=docker&logoColor=white)](https://github.com/izm1chael/mailhook/pkgs/container/mailhook)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/izm1chael/mailhook/badge)](https://scorecard.dev/viewer/?uri=github.com/izm1chael/mailhook)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/12986/badge)](https://www.bestpractices.dev/projects/12986)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go&logoColor=white)](app/go.mod)

A self-hosted email security gateway. MailHook monitors IMAP mailboxes over IDLE, runs
every incoming message through a multi-engine scanning pipeline, and automatically
quarantines or deletes threats. It provides a web dashboard for review, release, audit,
and allow/block-list management.

MailHook ships as a single Go binary (CGO is used for YARA) and runs alongside Rspamd and
ClamAV. This README is the full documentation: it covers features, architecture, every
supported installation and deployment method, configuration, operations, and development.

## Table of contents

1. [Overview](#overview)
2. [Features](#features)
3. [Architecture](#architecture)
4. [Requirements](#requirements)
5. [Generating the required secrets](#generating-the-required-secrets)
6. [Installation and deployment](#installation-and-deployment)
   - [Method 1: Docker Compose (recommended)](#method-1-docker-compose-recommended)
   - [Method 2: Docker Compose with the AI scanner tier](#method-2-docker-compose-with-the-ai-scanner-tier)
   - [Method 3: All-in-one single container](#method-3-all-in-one-single-container)
   - [Method 4: Debian / Ubuntu (.deb) with systemd](#method-4-debian--ubuntu-deb-with-systemd)
   - [Method 5: RHEL / Fedora (.rpm) with systemd](#method-5-rhel--fedora-rpm-with-systemd)
   - [Method 6: Build from source and run the binary](#method-6-build-from-source-and-run-the-binary)
7. [Configuration reference](#configuration-reference)
8. [The AI scanner tier (optional)](#the-ai-scanner-tier-optional)
9. [Running behind a reverse proxy](#running-behind-a-reverse-proxy)
10. [Operations](#operations)
11. [Using the dashboard](#using-the-dashboard)
12. [Development](#development)
13. [Project layout](#project-layout)
14. [Security model](#security-model)
15. [Troubleshooting](#troubleshooting)
16. [License](#license)

## Overview

MailHook connects to one or more IMAP accounts, watches the inbox using IMAP IDLE, and
processes new mail as it arrives. Each message is scanned concurrently by a set of
engines, a verdict engine combines the results, and MailHook takes an IMAP action:
leave the message in place, flag it, move it to a quarantine folder, or delete it.
Operators review and manage quarantined mail through the built-in web dashboard.

Everything is stored locally in SQLite. There is no external database and no cloud
dependency, although optional reputation services (VirusTotal, AbuseIPDB) can be enabled
with API keys.

## Features

- IMAP IDLE ingestion for one or more mailboxes, with a periodic recovery sweep that
  catches anything missed during reconnects.
- A concurrent, multi-engine scanning pipeline run per message:
  - Rspamd for spam scoring, ClamAV for malware, YARA for custom rules.
  - URL threat feeds: URLhaus, OpenPhish, PhishTank, ThreatFox (kept in an in-memory index).
  - URL unshortening that follows redirect chains with an SSRF-safe dialer.
  - Newly registered domain (NRD) detection via RDAP.
  - IP reputation (AbuseIPDB), plus VirusTotal and MalwareBazaar hash lookups.
  - HTML smuggling and hidden-text / zero-font heuristics.
  - An optional ONNX AI tier (DistilBERT phishing plus a DGA CNN) behind the `ai` build tag.
- A prioritized verdict engine that maps results to pass, flag, quarantine, or delete,
  and fails closed (quarantine for manual review) when a critical scanner is unavailable.
- A quarantine workflow: move to quarantine, release back to the inbox, delete, and
  re-scan. IMAP state and the local database are kept in sync.
- A web dashboard built with Tailwind and Alpine.js, served from the binary, with live
  updates over Server-Sent Events, quarantine management, allow/block lists, statistics,
  and an audit log.
- Security-by-default: AES-256-GCM encryption of stored IMAP credentials and API keys,
  bcrypt admin authentication with rate-limited login, CSRF protection, and a strict
  nonce-based Content Security Policy with no `unsafe-inline` and no `unsafe-eval`.
- Retrospective threat-feed claw-back that re-evaluates recently clean mail against
  updated feeds and quarantines newly recognized threats.

## Architecture

```
         IMAP (IDLE)                          +-------------+
   mailbox ------------------>  MailHook  --->|   Rspamd    |
                                 |    |        +-------------+
   quarantine / delete <---------+    +------->|   ClamAV    |
        (IMAP actions)            scanners      +-------------+
                                 |
                                 +-- SQLite (scans, audit, allow/block lists)
                                 +-- Web dashboard (HTTP, CSP, SSE)
```

MailHook talks to Rspamd over HTTP and to ClamAV over the clamd TCP protocol. In the
recommended Docker deployment these run as separate containers on a private network. In
the all-in-one image they run as supervised processes inside a single container. On a
bare host they run as their own services.

## Requirements

- A host that can run either Docker (recommended) or a Linux service.
- Rspamd and ClamAV reachable from MailHook.
- For source builds: Go 1.26 or newer, a C toolchain, and libyara 4.3 or newer.
- A mailbox that supports IMAP with IDLE.

Default ports: web dashboard `8080`, Rspamd `11333`, ClamAV `3310`.

## Generating the required secrets

MailHook refuses to start unless three secrets are set, and it rejects the placeholder
values shipped in the examples. Generate them once:

```bash
# CSRF signing key (must be at least 32 characters)
openssl rand -hex 32

# Database encryption key (must be exactly 64 hex characters = 32 bytes)
openssl rand -hex 32

# Admin password as a bcrypt hash (cost 12)
htpasswd -nbBC 12 admin 'your-strong-password' | cut -d: -f2
```

These map to `MAILHOOK_CSRF_SECRET`, `MAILHOOK_DB_ENCRYPTION_KEY`, and
`MAILHOOK_ADMIN_PASSWORD_BCRYPT`. The Makefile target `make setup-password` can generate
the bcrypt hash for you.

## Installation and deployment

Six methods are supported. Most operators should use Method 1.

### Method 1: Docker Compose (recommended)

This brings up MailHook, Rspamd, and ClamAV as three hardened containers on a private
network, with the dashboard published on loopback only.

```bash
git clone https://github.com/izm1chael/mailhook.git
cd mailhook

cp .env.example .env                  # then fill in the three secrets above
cp config.example.yaml config.yaml    # then add your IMAP account(s)

docker compose up -d --build
```

The dashboard is then available on `http://127.0.0.1:8080`. ClamAV downloads its virus
database on first start, which can take a few minutes, so `/health` may report ClamAV as
unavailable until that finishes.

Useful wrappers:

```bash
make up        # docker compose up -d --build
make down      # docker compose down
make logs      # follow logs
```

### Method 2: Docker Compose with the AI scanner tier

The AI tier adds DistilBERT phishing detection and a DGA CNN. It requires model files
(see [The AI scanner tier](#the-ai-scanner-tier-optional)) and is layered on with an
override file:

```bash
docker compose -f docker-compose.yml -f docker-compose.ai.yml up -d --build
```

### Method 3: All-in-one single container

`app/Dockerfile.allinone` packages MailHook, Rspamd, and ClamAV into one container,
supervised by s6-overlay. This is convenient for single-node hosts and for testing.
It uses more memory than running MailHook alone, because ClamAV holds its signature
database in RAM.

```bash
docker build -f app/Dockerfile.allinone -t mailhook:allinone .

docker run -d --name mailhook \
  -p 127.0.0.1:8080:8080 \
  --env-file .env \
  -v "$PWD/config.yaml:/etc/mailhook/config.yaml:ro" \
  -v mailhook-data:/data \
  mailhook:allinone
```

### Method 4: Debian / Ubuntu (.deb) with systemd

Build a native package with nfpm and install it. The package installs the binary to
`/usr/local/bin/mailhook`, a hardened systemd unit, and config under `/etc/mailhook`. It
declares `clamav-daemon`, `clamav-freshclam`, and `rspamd` as dependencies so they are
installed automatically.

```bash
cd app && make package-deb         # produces ../dist/mailhook_<version>_<arch>.deb
sudo apt install ./dist/mailhook_*.deb
```

After install:

```bash
# Edit the environment file and add the three secrets (see above).
sudoedit /etc/mailhook/mailhook.env

# Add your IMAP account(s).
sudoedit /etc/mailhook/config.yaml

sudo systemctl enable --now mailhook
systemctl status mailhook
journalctl -u mailhook -f
```

The systemd unit runs as a dedicated `mailhook` user with hardening enabled
(`NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, an empty capability set, and a
system-call filter). Runtime data lives in `/var/lib/mailhook` and feed caches in
`/var/cache/mailhook`.

### Method 5: RHEL / Fedora (.rpm) with systemd

The RPM is equivalent to the DEB and depends on `clamd` and `rspamd`.

```bash
cd app && make package-rpm         # produces ../dist/mailhook-<version>.<arch>.rpm
sudo dnf install ./dist/mailhook-*.rpm
```

Then configure `/etc/mailhook/mailhook.env` and `/etc/mailhook/config.yaml` and enable
the service exactly as in Method 4. AI-variant packages are available with
`make package-deb-ai` and `make package-rpm-ai`.

### Method 6: Build from source and run the binary

```bash
cd app
make build                  # standard binary at ../bin/mailhook
# or: make build-ai         # include the ONNX AI tier (-tags ai)
```

Run it with the configuration provided through environment variables, pointing it at your
own Rspamd and ClamAV:

```bash
export MAILHOOK_ADMIN_PASSWORD_BCRYPT='...'
export MAILHOOK_CSRF_SECRET='...'
export MAILHOOK_DB_ENCRYPTION_KEY='...'
export MAILHOOK_RSPAMD_URL='http://127.0.0.1:11333'
export MAILHOOK_CLAMAV_ADDR='127.0.0.1:3310'
export MAILHOOK_CONFIG='./config.yaml'
../bin/mailhook
```

Source builds need libyara installed (4.3 or newer). The provided Dockerfile compiles
YARA from source for reproducibility, and the native packages link it statically so no
runtime libyara dependency is required.

## Configuration reference

Global settings come from environment variables. Per-account IMAP settings come from a
YAML file (`config.yaml`). See `.env.example` and `config.example.yaml` for the complete,
commented set. The most important variables:

| Variable | Default | Purpose |
|---|---|---|
| `MAILHOOK_ADMIN_USER` | `admin` | Dashboard username |
| `MAILHOOK_ADMIN_PASSWORD_BCRYPT` | (required) | Bcrypt hash of the admin password |
| `MAILHOOK_CSRF_SECRET` | (required) | HMAC key for CSRF tokens, 32+ chars |
| `MAILHOOK_DB_ENCRYPTION_KEY` | (required) | 64-hex-char AES-256 key for secrets at rest |
| `MAILHOOK_LISTEN` | `0.0.0.0:8080` | Web listen address |
| `MAILHOOK_RSPAMD_URL` | `http://rspamd:11333` | Rspamd endpoint |
| `MAILHOOK_CLAMAV_ADDR` | `clamav:3310` | ClamAV (clamd) address |
| `MAILHOOK_YARA_RULES_DIR` | `/rules` | Directory of `.yar` rule files |
| `MAILHOOK_SPAM_SCORE` | `5.0` | Rspamd score at/above which mail is quarantined |
| `MAILHOOK_REJECT_SCORE` | `15.0` | Rspamd score at/above which mail is deleted |
| `MAILHOOK_VT_API_KEY` | empty | VirusTotal key (empty disables it) |
| `MAILHOOK_ABUSEIPDB_KEY` | empty | AbuseIPDB key (empty disables it) |
| `MAILHOOK_DATA_DIR` | `/data` | Stored EML and database location |
| `MAILHOOK_DB_PATH` | `/data/mailhook.db` | SQLite database path |
| `MAILHOOK_RETENTION_DAYS` | `30` | Retention for clean-mail EML (when retained) |
| `MAILHOOK_EML_QUARANTINE_RETENTION_DAYS` | `90` | Retention for quarantined EML |
| `MAILHOOK_TRUSTED_PROXIES` | empty | CIDRs whose `X-Forwarded-For` is trusted |
| `MAILHOOK_METRICS_ALLOWED_CIDRS` | `127.0.0.1/32,::1/128` | CIDRs allowed to reach `/metrics` and `/api/scan` |
| `MAILHOOK_TRUSTED_AUTHSERV_ID` | empty | authserv-id whose `Authentication-Results` are trusted |
| `MAILHOOK_REDACT_WEBHOOK_PII` | `false` | Mask From and Subject in ntfy/webhook payloads |
| `MAILHOOK_INSECURE_COOKIES` | `false` | Disable the Secure cookie flag (local HTTP dev only) |
| `MAILHOOK_LOG_LEVEL` / `MAILHOOK_LOG_FORMAT` | `info` / `json` | Logging |

Per-account IMAP configuration (`config.yaml`):

```yaml
accounts:
  - name: primary            # unique label, no spaces or slashes
    host: imap.example.com
    port: 993
    user: security@example.com
    pass: app-password
    mailbox: INBOX           # folder to monitor
    quarantine: Quarantine   # folder threats are moved to (created if missing)
    tls_skip_verify: false   # set true only for self-signed test servers
```

Account passwords in `config.yaml` are migrated into the database on startup and encrypted
at rest with `MAILHOOK_DB_ENCRYPTION_KEY`. Accounts can also be managed at runtime from
the Settings page in the dashboard.

## The AI scanner tier (optional)

The AI tier is excluded from the default build. To use it, build with `-tags ai`
(`make build-ai`) and provide model files. Helpers:

```bash
cd app
make models-dl       # fetch the Tranco greylist
make models-bert     # export the DistilBERT phishing model to ONNX
make models-dga      # build the DGA CNN model (see scripts/export_dga_onnx.py)
make build-ai        # build the AI-enabled binary
```

A missing model is non-fatal: that sub-scanner is skipped and logged, while the rest of
the pipeline continues to run.

## Running behind a reverse proxy

The dashboard speaks plain HTTP and is meant to sit behind a TLS-terminating reverse
proxy (Caddy, nginx, Traefik) in production. When you do this:

1. Set `MAILHOOK_TRUSTED_PROXIES` to the proxy's CIDR(s) so client IPs are read from
   `X-Forwarded-For` correctly (used for login rate-limiting and audit logs).
2. Keep `MAILHOOK_METRICS_ALLOWED_CIDRS` tight. It defaults to loopback only and gates
   both `/metrics` and the benchmarking `/api/scan` endpoint.
3. Do not forward `/metrics` or `/api/scan` to untrusted clients.

The dashboard sends HSTS and a strict CSP, so it expects to be served over HTTPS.

## Operations

Endpoints:

- `GET /healthz` is an unauthenticated liveness probe used by container health checks.
- `GET /health` (authenticated) returns full component health and today's stats, and
  returns 503 when a critical component is degraded.
- `GET /metrics` exposes Prometheus metrics, restricted by `MAILHOOK_METRICS_ALLOWED_CIDRS`.

Maintenance runs automatically at 03:00 local time: EML retention pruning, IP-reputation
cache sweep, an integrity check, and a compacted database backup (VACUUM INTO). Threat
feeds refresh on the interval set by `MAILHOOK_FEED_REFRESH_INTERVAL` (default 6h), and
can be refreshed on demand from the Settings page.

Backups: the SQLite database and the `emls` directory under the data dir hold all state.
Back up `MAILHOOK_DATA_DIR` (and keep `MAILHOOK_DB_ENCRYPTION_KEY` safe, since stored
credentials cannot be decrypted without it).

Updating a Docker deployment:

```bash
git pull
docker compose up -d --build
```

## Using the dashboard

- Dashboard: recent scans, verdict and status, and live updates as new mail is processed.
- Quarantine: review held messages, preview sanitized HTML in a sandboxed frame, release
  to the inbox, delete, re-scan, or learn-as-spam. Bulk actions are supported.
- Lists: manage allow and block lists by address or domain, including bulk import.
- Stats: per-verdict and per-sender breakdowns over time.
- Audit: a record of every automated and manual action.
- Settings: thresholds, API keys, notifications, scanner toggles, endpoints, accounts,
  and password change.

## Development

```bash
cd app
make build           # standard binary
make build-ai        # AI-enabled binary
make test            # full test suite
make test-race       # race detector
make test-cover      # coverage profile
make vet             # go vet
make lint            # golangci-lint (if installed)
make simulate        # verdict-engine scenario comparison (standard vs AI)
make bench           # pipeline benchmarks
```

Docker image builds: `make docker-build`, `make docker-build-ai`,
`make docker-build-standard`.

## Project layout

```
app/                       Go source
  pipeline/                message parsing, scanner fan-out, verdict engine
  scanners/                rspamd, clamav, yara, urlcheck, urlunshorten, nrd, vt, ...
  imap/                    IMAP listener, actions, recovery, manager
  web/                     HTTP server, handlers, templates, embedded static assets
  db/                      models, migrations, SQLite access, at-rest encryption
  config/                  configuration loading and validation
  notify/                  ntfy and webhook notifications
  cmd/                     seed, simulate, bench, soak helpers
  Dockerfile               standard image
  Dockerfile.ai            AI-variant image
  Dockerfile.allinone      single-container image (s6-overlay)
rules/                     YARA rules
rspamd-config/             Rspamd local.d overrides
packaging/                 nfpm DEB/RPM config, systemd unit, all-in-one assets
docker-compose.yml         main stack (mailhook + rspamd + clamav)
docker-compose.ai.yml      AI-variant override
docker-compose.bench.yml   benchmarking stack
```

## Security model

- Admin authentication uses bcrypt with per-IP login rate-limiting and lockout.
- Sessions are HttpOnly, SameSite=Strict cookies; CSRF uses a signed double-submit token.
- The dashboard sets a nonce-based CSP with no `unsafe-inline` and no `unsafe-eval`,
  plus `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, and HSTS.
- IMAP credentials and API keys are encrypted at rest with AES-256-GCM.
- Outbound URL resolution (unshortening, RDAP, webhooks) uses an SSRF-safe dialer that
  resolves once and refuses non-public addresses.
- Quarantined email HTML is sanitized and previewed only inside a sandboxed iframe.

Run MailHook behind HTTPS, set the trusted-proxy and metrics CIDRs to match your
deployment, and rotate the example secrets before going live.

## Troubleshooting

- `/health` shows ClamAV unavailable on first start: ClamAV is still downloading its
  signature database. Wait a few minutes.
- Startup exits immediately complaining about secrets: one of the three required secrets
  is missing or still set to its placeholder value.
- Login does not persist over plain HTTP during local testing: set
  `MAILHOOK_INSECURE_COOKIES=true` (never in production).
- `/metrics` or `/api/scan` returns 403: the caller's IP is not in
  `MAILHOOK_METRICS_ALLOWED_CIDRS`, or `X-Forwarded-For` is not trusted because
  `MAILHOOK_TRUSTED_PROXIES` is unset.

## License

Released under the [MIT License](LICENSE). Copyright (c) 2026 izm1chael.
