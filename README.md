# Partout

[![CI](https://github.com/blawesom/partout/actions/workflows/ci.yml/badge.svg)](https://github.com/blawesom/partout/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/blawesom/partout)](https://github.com/blawesom/partout/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

> **Status: beta — the 1.0-scoped beta: all 1.0 features in, gathering feedback
> before the 1.0 GA flip.** Expect the occasional rough edge and occasional breaking
> change before 1.0; back up your `partout.db` regularly. What shipped in which
> release: [docs/roadmap.md](docs/roadmap.md) — the single status source.

**Partout** is a self-hosted control plane for Linux fleets: one Go binary to discover,
observe, execute against, configure, patch, and orchestrate work across hosts — safely,
auditably, and verifiably — with a web UI, an MCP server for AI assistants, and a built-in
LLM assistant. Single binary, no editions, everything free
([LICENSE](LICENSE), [PRD.md](PRD.md)).

It unifies the **observe → act → verify** loop in one place: a policy deny-list gates
every dispatch (with optional human approval), the agent re-checks each action locally
(fail-closed), and every action lands in an append-only audit log sealed by a
cryptographic hash chain (`partout ctl audit verify`).

## Requirements

- Linux (amd64/arm64) for server and agents; Go 1.26+ only if building from source.
- No database to install (embedded SQLite), no CDN at runtime (the UI is served
  same-origin, works fully offline).

## Quick start (60 seconds)

One-process demo — server **and** a co-located agent, no enrollment needed:

```bash
go build -o partout ./cmd/partout
PARTOUT_MODE=embedded PARTOUT_ADMIN_PASSWORD='change-me-123' ./partout
```

Expected output: the server listens on `127.0.0.1:8443` (loopback + plaintext is the
local-dev posture). Open **http://localhost:8443**, sign in as `admin` /
`change-me-123` — the Fleet page shows one host, state `connected`.

Verify it works from the CLI:

```bash
PARTOUT_SERVER=localhost:8443 ./partout ctl auth login --username admin --password 'change-me-123'
PARTOUT_SERVER=localhost:8443 ./partout ctl hosts                        # saved session token is used automatically
PARTOUT_SERVER=localhost:8443 ./partout ctl run --selector all -- hostname
PARTOUT_SERVER=localhost:8443 ./partout ctl audit verify                  # tamper-evidence check on the audit chain
```

(For a real server, see below. Full walkthrough: [docs/getting-started.md](docs/getting-started.md).)

## Install a server on a real host

No toolchain or git checkout needed — the release installer bundle ships the static
binary + `install-server.sh` + systemd units:

```bash
VERSION="$(curl -s https://api.github.com/repos/blawesom/partout/releases/latest | grep '"tag_name"' | cut -d'"' -f4)"
curl -sLO "https://github.com/blawesom/partout/releases/latest/download/partout_install_${VERSION#v}_linux_amd64.tar.gz" \
     -O "https://github.com/blawesom/partout/releases/latest/download/SHA-256SUMS"
sha256sum -c SHA-256SUMS --ignore-missing
tar xzf "partout_install_${VERSION#v}_linux_amd64.tar.gz"
sudo bash "install_${VERSION#v}_linux_amd64/install-server.sh" \
     --binary "install_${VERSION#v}_linux_amd64/partout" --tls on \
     --tls-names <server-ip-or-fqdn>
```

Then enroll agents over the fleet's SSH (one command, fingerprint-confirmed — no silent
TOFU): `partout ctl provision new --host user@web01`. Details, mTLS bootstrap, reverse
proxies, Docker/systemd/Helm: [docs/deployment.md](docs/deployment.md).

## When to use / not use

- **Use it** when you want one system that reads (facts, certs, services), writes
  (commands, files, packages, jobs — all policy-gated and audited), and proves it
  (hash-chained audit log, live alerts) across a fleet of Linux hosts.
- **Not yet** if you need non-Linux agents, a hosted/SaaS control plane, or
  multi-region HA — see non-goals in [PRD.md](PRD.md) §13. Beta caveat: breaking changes
  are still possible before 1.0 ([docs/roadmap.md](docs/roadmap.md)).

## Troubleshooting the top stalls

- **TLS off → binds loopback only** (safe default). To serve beyond the machine:
  `PARTOUT_TLS=on` (bootstraps a local root CA, HTTPS + mTLS) or put it behind your own
  reverse proxy — [docs/deployment.md](docs/deployment.md) §1.3. `partout doctor`
  pre-flights a start and names exactly what would block it.
- **Can't reach the UI from your workstation?** the port is often firewalled to the
  fleet — SSH-tunnel it (`ssh -N -L 8443:<server>:8443 user@<server>`); see
  [docs/deployment.md](docs/deployment.md) §1.2.
- **Host shows disconnected?** check the agent unit and `partout ctl hosts`; runbooks in
  [docs/operations.md](docs/operations.md) §6.

## CLI

`partout ctl` drives everything the UI does. The full command set: `auth · enroll-token · hosts · run · exec · audit · policy ·
preset · approvals · alerts · provision · ca · tls · files · sessions · jobs · tasks ·
playbooks · packages · cve · services · secrets · update · elevation · db-backup · external-data` (plus the
top-level `partout doctor`, `partout selftest`, `partout update`, and
`partout uninstall`). Full reference: `partout ctl help`, plus a
representative tour in [docs/operations.md](docs/operations.md). (This list is pinned
against the dispatch by `TestCtlUsageContract` in CI — update both together.)

## Documentation

| Doc | What it covers |
|---|---|
| [docs/getting-started.md](docs/getting-started.md) | Guided 5-minute walkthrough (first host, first command, audit check) |
| [docs/architecture.md](docs/architecture.md) | Architecture: modes, AgentStream protocol, policy chain, storage, security |
| [docs/deployment.md](docs/deployment.md) | Install paths, TLS/reverse proxy, topology, full config reference |
| [docs/operations.md](docs/operations.md) | Day-2 ops: backups, upgrades, runbooks, troubleshooting, compliance |
| [docs/roadmap.md](docs/roadmap.md) | Milestone plan & status + shipped feature deep-dives |
| [docs/assistant.md](docs/assistant.md) | The built-in LLM assistant + MCP server |
| [PRD.md](PRD.md) | Product spec, positioning, decisions log, non-goals |
| [docs/dev/](docs/dev/) | Internal: UX research, walkthrough instrument, proposals |

Screenshots: [docs/screenshots/](docs/screenshots/). Architecture diagram:
[partout-architecture.svg](partout-architecture.svg).

## Contributing & security

Contributions welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) (docs change in the same
PR as behavior; CI runs tests, link checks, and the quickstart snippet). Security issues:
see [SECURITY.md](SECURITY.md) — please report privately, do not open public issues.

## License

[MIT](LICENSE) — single binary, all features free, self-hosted.
