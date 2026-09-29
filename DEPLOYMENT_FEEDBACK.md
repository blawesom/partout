# Deployment feedback — ccc.laplane.net (v0.7.2, 2026-09-29)

Field notes from deploying partout v0.7.2 on a Rocky 10 host with the existing
haproxy 3.0.5 as TLS edge. Topology: `partout-server` + `partout-agent` systemd
units on the managed host, haproxy multi-SNI on :443, Let's Encrypt, http 301.

Everything worked. The friction points below are grouped by where they bite.

## A. Host-side process gaps (found during this deploy)

1. **Backup runbook is documented but unimplemented.** `docs/operations.md`
   prescribes a nightly `sqlite3 .backup` of the DB and commit-not-backup for
   config — but the deployed host had no backup timer and no config repo.
   Data-loss risk is the top item: a systemd timer for
   `/var/lib/partout/partout.db` (with retention) and a git repo for
   `/etc/partout/` + `/etc/haproxy/haproxy.cfg` should be day-1 steps in the
   deploy checklist.
2. **Cert renewal hooks are per-domain copy-paste.** The existing host had
   `renewal-hooks/post/haproxy-vpn.sh` (stale, pointing at a 0-byte pem) and we
   added `haproxy-ccc.sh` following the same pattern. Two hooks that each fire
   on every renewal of any cert. Suggest a single idempotent rebundle script
   driven by what haproxy actually references.
3. **Standalone issuance stops the whole reverse proxy** (~15s, all vhosts) on
   every renewal. DNS-01 (if the domain's DNS provider has API access) or
   http-01 via an haproxy ACL on `/.well-known/acme-challenge` would make
   renewals zero-downtime.
4. **dnf was already broken on the host** (GPG signature failures in
   `grafana` + `tailscale-stable` repos) — every dnf command silently failed
   until `--disablerepo=grafana,tailscale-stable`. Pre-existing infra hygiene,
   but it shaped the deploy (had to disable repos just to *check* package
   availability). Fix the repo keys, or the next incident repeats this.
5. **Plaintext 8443 is publicly reachable** (firewall left off on this host).
   443 via haproxy is the supported path, see C11 for the root-cause fix.

## B. Observability / ops

6. **Dogfood partout on itself.** The host is now its own fleet member. Add
   alert rules: `haproxy.service` failed, cert `ccc.laplane.net` < 21 days,
   `partout-server`/`partout-agent` failed. Limitation: partout can't alert on
   its own death — an external observer (cron from another box hitting
   `/healthz`, or a second fleet member) is still needed.
7. **Upgrade is manual** (fetch release, verify SHA-256SUMS, swap binary,
   restart, healthz — per `docs/operations.md`). A small script or a partout
   task would make version bumps one command instead of a checklist.

## C. Upstream repo improvements (cheap wins)

8. **Ship `deploy/haproxy/partout.cfg`** and a "exposing via an existing
   reverse proxy" section in `docs/deployment.md`. Today only Caddy/nginx are
   covered, but this deploy proves the haproxy pattern. Gotchas worth
   documenting:
   - multi-SNI: second `crt` path on the same 443 bind line;
   - `timeout client` on a backend is **silently ignored** in http mode (HAProxy
     prints a warning) — it belongs on the **frontend** for long-lived
     SSE/PTY streams (use 1h; defaults are 1m/5m and will drop idle sessions);
   - `/healthz` healthcheck on the backend;
   - cert bundle = `fullchain.pem` + `privkey.pem` concatenated,
     owned by the haproxy user, 0640.
9. **`scripts/install-server.sh`** — idempotent bootstrap: system user, data
   dir, env file with secrets generated once, unit install, healthz verify.
   Compresses a ~15-minute manual sequence to one run.
10. **Embedded-mode systemd unit** — `deploy/systemd/` only ships
    server + agent units; the one-process embedded mode (documented in the
    README as the fastest path) has no unit for it.
11. **`PARTOUT_ADDR`/bind-address knob** — the server hardcodes
    `net.Listen("tcp", ":<port>")` (all interfaces) in `cmd/partout/main.go`;
    there is no way to bind loopback-only. That's what forces the
    firewall-dependent story in A5.
12. **Minor doc/flag drift**: certbot 4.x removed `--ecdsa` in favor of
    `--key-type ecdsa`; if any docs/examples reference the old flag they will
    fail on current certbot.

## Priority order

1 → 2/4 (data loss; renewal & package-manager failure modes) → 6 (manual
discovery of outages) → 8–11 (future deploys get faster and safer) → 3, 7, 10–12.
