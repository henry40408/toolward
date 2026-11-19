# CLAUDE.md

Guidance for Claude Code (claude.ai/code) working in this repository.

## Overview

toolward is an MCP proxy written in Go. The agent talks to one stdio server (`toolward serve`); toolward starts the real MCP servers behind it and keeps their credentials in the macOS Keychain. See `README.md` for behaviour and `ARCHITECTURE.md` for the package map.

## Commands

Run from the repository root. The Go version comes from `go.mod` alone (`go` and `toolchain` lines); CI installs nothing version-specific.

- Build: `go build -o bin/toolward ./cmd/toolward`
- Tests: `go test -race ./...`; one test: `go test ./internal/redact -run TestName`
- Coverage (as CI, on macOS): `TOOLWARD_COVERDIR=$PWD/covdata go test -mod=vendor -coverprofile=coverage.out ./...`, then `go tool covdata textfmt -i=covdata -o coverage-bin.out` and append it without its `mode:` line. `-coverprofile` ignores the binary that `cmd/toolward`'s `TestMain` builds and runs; with `TOOLWARD_COVERDIR` set, `TestMain` builds it with `-cover`.
- Lint (CI-enforced): `golangci-lint fmt --diff ./...` (must print nothing) and `golangci-lint run ./...`. The config is `.golangci.yml` (the defaults plus the gofmt formatter). `run` does not check formatting, so `fmt --diff` is a separate step. Suppress a finding with `//nolint:<linter> // reason`; `//lint:ignore` is not honoured. Error strings in `internal/oauth` are user-facing text, so their ST1005 findings carry a `//nolint:staticcheck` comment. CI installs the linter through `golangci/golangci-lint-action` with `install-only: true` and no `version:` input, so the linter release floats with the action and dependabot tracks only the action.
- Cross-platform check: `GOOS=linux golangci-lint run ./...`. The Keychain store builds only on darwin; CI lints and tests on macOS and Linux for that reason.
- Mutation testing (the `mutation` job; advisory, `continue-on-error`; pull requests mutate only the changed lines, pushes to main the whole module): `go clean -testcache`, then `go run github.com/go-gremlins/gremlins/cmd/gremlins@v0.6.0 unleash .`, or with `--diff origin/main` for the changed lines. The efficacy threshold (the run fails when efficacy is 95% or below) and the `vendor/` exclusion live in `.gremlins.yaml`. **Never pass `--threshold-efficacy` on the command line**: gremlins v0.6.0 reads a float64 flag through viper as a string, gets 0 ("no threshold") and always exits 0; the same value from the yaml works. A `--diff` run with no mutable Go line reports 0 mutants and a 0% score; the CI pull request step treats that as a pass. A cached test run makes gremlins' timeouts near zero, so most mutants "time out" and the score means nothing.
- Dependency checks (CI-enforced): `go mod tidy -diff`, `go mod vendor`, then `git status --porcelain -- vendor go.mod go.sum` must print nothing, and `go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...`.
- Licence check (CI-enforced, in the `deps` job): `GOROOT=$(go env GOROOT) go run github.com/google/go-licenses/v2@v2.0.1 check ./... --include_tests --allowed_licenses=<list>`. The allowed list lives in `ci.yml` (`ALLOWED_LICENSES`) and nowhere else. `GOROOT` must be set explicitly or go-licenses fails on standard-library packages. `report ./... --include_tests` prints each module's licence. A dependency reported as Unknown or outside the list fails CI; do not widen the list or swap the module without asking.
- The real Keychain test is skipped unless `TOOLWARD_KEYCHAIN_TEST=1` (it may prompt).

Third-party modules are **vendored and committed** (`vendor/`); builds and tests use `-mod=vendor` (Go selects it while `vendor/` exists). To add or update a dependency: `go get <module>@<version>`, `go mod tidy`, `go mod vendor`, and commit `go.mod`, `go.sum` and `vendor/` together.

## Rules

- **Dependencies:** do not add or update a module, GitHub Action or tool that was published less than 7 days ago. Check the release date first (`curl -s https://proxy.golang.org/<module>/@v/<version>.info`).
- **stdout of `serve`:** it carries only MCP JSON-RPC. Every log line goes to stderr and starts with `toolward: `. Do not add a print to stdout in that path.
- **Error strings are a user-facing contract.** They match the former Rust build word for word, and tests pin them. Wrap with `%v`, not `%w`, where the old text chained causes with `: `. Never put a secret or config text in an error or a log line; use account names.
- **No MCP SDK in production code.** `internal/mcpwire` is the wire layer; the Go SDK is imported by tests only (see `ARCHITECTURE.md`).
- **Config is strict JSONC** (via `hujson`): comments and trailing commas only. Unquoted keys, single quotes and hex numbers are rejected, unlike in the Rust build.
- **Iteration order is sorted** (server names, env and header keys, references) so output is stable. Sorting is byte-wise.

## Test helpers

- `internal/testing/fakeupstream`: a stdio MCP server built with the Go SDK. Tests start it by running their own test binary again with `TOOLWARD_FAKE_UPSTREAM=1`; a `TestMain` that wants this calls `fakeupstream.Run()` first.
- `internal/testing/httpfake`: a local streamable HTTP MCP and OAuth server for the HTTP and `check` tests.
- `cmd/toolward/main_test.go` builds the binary once in `TestMain` and runs it. It passes no `HOME` and no `XDG_CONFIG_HOME`, so a test that forgets `--config` fails instead of reading a real config.
- Use the in-memory store in tests. Never touch the Keychain by default.

## Versioning & Release

The version is never stored in a manifest. `internal/version.Version()` returns the `-ldflags "-X github.com/henry40408/toolward/internal/version.version=$GIT_VERSION"` value when set (not empty, not `dev`), else the module version Go stamps from VCS, else `unknown`. Release with `gh release create --generate-notes`. Never hand-edit versions or run `git tag`.

## Conventions

- GitHub Actions are pinned by commit SHA with the tag as a trailing comment (`uses: owner/repo@<sha> # v1.2.3`).
- Keep functions short, use early returns, and pass a parameter struct for more than 4 parameters.
