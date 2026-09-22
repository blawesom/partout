# Partout — Validation results

**What this validates:** the core architecture claim — an **outbound-only agent**
reaching the server over a real network, **no inbound ports** on the agent host, with an
**mTLS-protected gRPC stream** and credentials that survive restarts. Sheet:
[validation-multihost.md](validation-multihost.md).

---

## Run 1 — 2026‑09‑22 (internet‑routed)

| | |
|---|---|
| Binary | v0.1.1 (commit `44059a5`; built from `ca41a37` — docs‑only diff verified; md5 `50a62cd6fd5cceabdcfeaa4cd2be5960`, Go 1.25) |
| Arch | amd64, static |
| Server A | `ccc` — 5.104.101.250 (ccc.laplane.net), RHEL‑family, curl 8.12.1 / OpenSSL 3.5.5 |
| Agent B | `dev` (dev.laplane.net), x86‑64 |
| Network | **Internet** (dev → 5.104.101.250:8443, L4 open, no proxy) |

### Results

| Check | Result |
|---|---|
| Plaintext (h2c) enroll → connect → run → restarts | **PASS** (prior run; code unchanged, not re-run this pass) |
| TLS/mTLS steps 1–7 | **PASS** |
| Server‑restart reconnect | **PASS** — ~1–2 s (server ready 14:58:37, agent "reconnecting in 1s" 14:58:37, authenticated 14:58:38; clocks ~0.3 s apart) |
| Agent‑restart, no re‑enrollment | **PASS** — same `ag_d9eea348ddd8` / uuid `8218f92e…`; leaf/key from persisted `/tmp/partout-val/agent-tls/tls`; **no new CSR** |
| Egress‑only invariant | **PASS** — `ss -ltnp` on the agent host: no partout listener, pre and post |
| mTLS enforcement | **PASS** — plaintext `curl` to the TLS port refused (exit 22); `https --cacert` → `{"status":"ok"}` |
| Command over mTLS | **PASS** — `exec_6ecd471877eb` succeeded, exit 0, 2 ms, output = agent host `id` (uid=1000 outscale) |
| Cleanup | **PASS** — both hosts verified: no partout process, no `/tmp/partout-val`, no `/tmp/partout`, no listener |

### Findings from the run

1. **SAN fix confirmed (audit bug #1):** with `--tls-names 127.0.0.1,5.104.101.250` the
   leaf was `SANs [127.0.0.1 5.104.101.250]` and enrollment succeeded — the prior
   `x509: cannot validate certificate for <A_IP>` is resolved. **Operator implication:**
   the dial address must always be in `--tls-names`/`PARTOUT_TLS_SERVER_NAMES`; the
   future provisioning step can pass it automatically.
2. **`ctl --ca-file` fix confirmed (audit bug #2):** `enroll-token`, `hosts`, `run` all
   work over HTTPS once the CA is supplied.
3. **Cached `server.crt` trap hit in practice:** a stale `partout`/`tls` dir from the
   earlier (pre‑audit) failed attempt was found on the agent host and pre‑cleaned; a
   fresh CA + leaf with correct SANs was generated. Reinforces the sheet's cleanup +
   fresh‑`--db` guidance.
4. **Reconnect timing within spec:** observed 1–2 s, consistent with the 1 s‑base
   doubling backoff (worst case ~10–16 s if mid‑backoff).

### Verdict

**Architecture claim verified over an internet‑routed network.** v0.1.1 is proven
stable for the core topology; no code defects found. Remaining risk is feature
completeness (M1 items), not foundation.

---

## Implications / next steps

- Foundation is de‑risked → proceed to **M1‑remaining** in the planned order:
  policy deny‑list (agent‑side re‑check) → host provisioning (fleet SSH) → offline
  spool → Postgres → embedded‑mode agent wiring.
- Multi‑machine testing now has a proven recipe: this run doubles as the template for
  regression‑testing v0.2+ (re‑run the sheet after each release tag).