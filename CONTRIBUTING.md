# Contributing to MailHook

## How to contribute

Bug reports, feature requests, and pull requests are welcome via GitHub:

- **Bug reports / feature requests:** open an issue at https://github.com/izm1chael/mailhook/issues
- **Pull requests:** fork the repository, make your changes on a feature branch, and open a PR against `main`
- **Security vulnerabilities:** report privately via GitHub Security Advisories (see [SECURITY.md](SECURITY.md))

## Build requirements

You will need:

- Go 1.26+ with CGO enabled
- libyara-dev and libssl-dev (Ubuntu: `sudo apt-get install libyara-dev libssl-dev`)
- All other dependencies are FLOSS and fetched automatically by `go mod download`

Build and test:

```bash
make build      # standard binary
make test       # unit + integration tests
make test-race  # tests with race detector
```

See the README for full development setup, including the optional AI tier.

## Coding standards

- **Format:** all Go code must be formatted with `gofmt` (enforced by `go vet` in CI)
- **Vet:** `go vet ./...` must pass with no warnings
- **Security:** `gosec` must pass with no new findings outside the documented exclusions
- **Tests:** new functionality should include tests; run `make test` before submitting
- **Comments:** only add comments where the *why* is non-obvious; avoid restating what the code does

CI runs automatically on every pull request and must pass before a PR can be merged.
