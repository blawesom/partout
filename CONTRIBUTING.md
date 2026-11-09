# Contributing to Partout

Thanks for helping. Partout is a single self-hosted Go binary; the web UI is a
buildless Vue 3 SPA embedded in the binary.

## Ground rules

- **Docs change in the same PR as behavior.** If your PR changes what a user
  sees or does, update `README.md` / `docs/` in the same commit — CI link-checks
  docs and executes the README quickstart snippet, so broken docs fail the build.
- Keep PRs small and reviewable; one logical change per PR.
- No telemetry, no external calls at runtime — the product must work fully
  offline.

## Setup

```bash
git clone <this repo> && cd partout
go build -o partout ./cmd/partout        # Go 1.26+
./partout selftest                       # quick self-check
```

Run the app locally for UI work:

```bash
PARTOUT_MODE=embedded PARTOUT_ADMIN_PASSWORD='dev-password' ./partout
# open http://localhost:8443 (admin / dev-password)
```

## Checks (all run in CI)

```bash
gofmt -l .                               # must be empty
go vet ./...
go build ./...
go test ./... -race -count=1
bash scripts/check-readme.sh             # README quickstart snippet + links smoke
```

## Layout

- `cmd/partout` — CLI + server/agent entrypoint
- `internal/api` — REST v1, SSE, embedded web UI (`internal/api/webui`)
- `internal/control` — dispatch orchestration (policy → approval → signed decision)
- `internal/agent` — the host agent (exec, files, sessions, guardrail, spool)
- `internal/store` — SQLite store + audit hash chain
- `internal/server/*` — server-side engines (approvals, jobs, updates, observe, …)
- `docs/` — user docs; `docs/dev/` — internal research/proposals

Architecture: [docs/architecture.md](docs/architecture.md). Product spec:
[PRD.md](PRD.md). Roadmap/status: [docs/roadmap.md](docs/roadmap.md).

## Reporting issues

- Bugs: open an issue with reproduction steps and `partout doctor` output.
- Security: see [SECURITY.md](SECURITY.md) — report privately.
