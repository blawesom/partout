# Security policy

Partout is a control plane for production hosts — a compromise of the server
means compromise of every managed host, so we take reports seriously.

## Reporting a vulnerability

**Please report privately — do not open a public GitHub issue.**

- Email: **security@blawesom.github.io** (or open a private vulnerability
  report via GitHub: *Security → Advisories → Report a vulnerability*).
- Include: affected version/commit, a minimal reproduction, and impact
  (what an attacker can do: read audit logs, dispatch commands, exfiltrate
  secrets, …).
- You will get an acknowledgement within 72 hours and a status update at
  least every 7 days until resolution. We will credit reporters in the
  release notes unless you prefer otherwise.

## Scope notes

- The audit log is sealed by a hash chain: verify it with
  `partout ctl audit verify` (or `GET /api/v1/audit/verify`, which also
  returns a signed chain head you can anchor out-of-band) — see
  [docs/operations.md](docs/operations.md) §4.1.
- Beta status (pre-1.0): the API and on-disk format may still change; do not
  expose the server beyond loopback or your own TLS-terminating proxy without
  `PARTOUT_TLS=on` (the server bootstraps a local root CA and serves HTTPS +
  mTLS on the agent stream).
- Out of scope: vulnerabilities in dependencies already reported upstream
  (we track them via `govulncheck` in CI); social engineering.

## Supported versions

Security fixes land on the latest release line; the beta (pre-1.0) line is
supported on a best-effort basis — upgrade to the newest release.
