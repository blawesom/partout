# Partout — Multi‑machine validation (v0.1.1)

**Goal:** prove the core topology over a *real* network — an **outbound‑only agent**
reaching a server with **no inbound ports** on the agent host — in both **plaintext**
and **TLS/mTLS** variants. Loopback smoke tests don't cover this: real routing, the
h2c/h2 demux under a real stack, and the mTLS handshake across a network.

**Binary under test:** tag `v0.1.1` (commit `44059a5`). Build once on a dev box with
Go ≥ 1.25:

```
git clone git@github.com:blawesom/partout && cd partout
git checkout v0.1.1
go build -o partout ./cmd/partout     # static single binary; copy to BOTH machines
```

*Audited against v0.1.1 (44059a5): all commands/expected output verified, including the
TLS-variant fixes for the server-leaf SAN, `ctl --ca-file` over HTTPS, and the agent's
persisted-material log line.*

Verify the target arch matches the agent host (`file partout` / `uname -m`).
No Go is needed on the two test machines — only the binary.

## Setup

| Role | Host | Needs |
|---|---|---|
| **server** | A | port `8443` reachable from B (same LAN/VPC, or firewall egress from B) |
| **agent** | B | **egress only** to A:8443 — confirm no inbound ports are opened on B |

Firewall check (on B, the agent host): nothing should be *listening*; only outbound
connects to A. This is the whole point — verify it:

```
# on B: should show NO partout listener
ss -ltnp | grep partout || echo "OK: no inbound listener"
```

Create a scratch dir on both: `mkdir -p /tmp/partout-val`.

---

## Variant 1 — plaintext (h2c)

1. **Server (A):**
   ```
   /path/to/partout --mode=server --port=8443 --db=/tmp/partout-val/partout.db
   ```
   *Expected:* `gRPC + REST + SSE on :8443, db …` then no error. Keep it running.
2. **Check (A):** `curl -sf http://127.0.0.1:8443/healthz` → `{"status":"ok"}`.
   Also from B: `curl -sf http://<A_IP>:8443/healthz` → `{"status":"ok"}`.
3. **Mint a token (A):**
   ```
   /path/to/partout ctl --server <A_IP>:8443 enroll-token
   ```
   *Expected:* `token: par_enr_…` + `expires: … (ttl 900s)`. Note the token.
4. **Agent (B):**
   ```
   PARTOUT_SERVER=<A_IP>:8443 PARTOUT_TOKEN=<token> \
     /path/to/partout --mode=agent --data-dir=/tmp/partout-val/agent
   ```
   *Expected:* `agent: enrolling with token …` → `agent: enrolled as ag_… (uuid …)`
   → `agent: connected to <A_IP>:8443`.
5. **Verify (A):**
   ```
   /path/to/partout ctl --server <A_IP>:8443 hosts
   ```
   *Expected:* one row, `STATE connected`.
6. **Run a command (A):**
   ```
   /path/to/partout ctl --server <A_IP>:8443 run --selector all -- uname -a
   ```
   *Expected:* `execution exec_… dispatched` → run `succeeded`, output = B's `uname -a`.
7. **Server restart (A):** `Ctrl-C`, then start the server again with the same
   `--db`. *Expected:* on restart the host flips to `disconnected`; the agent
   (B, still running, unmodified) reconnects — typically within a couple of seconds,
   worst case ~10–16 s if it is mid-reconnect-backoff (1 s base, ×2 per failure,
   60 s cap) when the server comes up — then `connected` again.
   *This is the key resilience check.*
8. **Agent restart (B):** `Ctrl-C`, start the agent again (same `--data-dir`,
   **no** `PARTOUT_TOKEN`). *Expected:* no re-enrollment; reconnects with the same
   `ag_…` id.

**Plaintext result:** ________ (PASS/FAIL — which step, if not)

---

## Variant 2 — TLS / mTLS

(Optionally stop the plaintext server from Variant 1 first.)

1. **Server (A), TLS:**
   ```
   /path/to/partout --mode=server --port=8443 --db=/tmp/partout-val/tls.db \
     --tls on --tls-names 127.0.0.1,<A_IP>
   ```
   *Expected:* `TLS enabled (CA in /tmp/partout-val/tls, SANs [127.0.0.1 <A_IP>])` then
   `gRPC + REST + SSE (TLS) on :8443`. First run **generates** the root CA + server
   leaf under `/tmp/partout-val/tls/`.
   - **`--tls-names` must include the address the agent dials** (`<A_IP>`). The agent
     verifies the server leaf strictly (no skip-verify); the default SANs are
     `localhost,127.0.0.1,<A-hostname>`, so without this the enroll in step 4 fails
     with `x509: cannot validate certificate for <A_IP>`. IP SANs are supported.
   - The leaf is **cached**: if you change `--tls-names` after first run, use a fresh
     `--db` (or delete `/tmp/partout-val/tls/server.crt`).
2. **Bootstrap the CA to B:** `scp /tmp/partout-val/tls/ca.crt B:/tmp/partout-val/`
   (one-time manual handoff; afterwards `partout ctl ca --ca-file ca.crt` works for
   future fetches). *Expected:* B has `/tmp/partout-val/ca.crt`.
3. **Mint a fresh token (A):** the TLS server has a **separate DB** (`tls.db`), so the
   Variant-1 token is unknown to it. The port is **HTTPS** now, so `ctl` needs the CA
   (without `--ca-file` it defaults to `http://` and fails with a protocol error):
   ```
   /path/to/partout ctl --server <A_IP>:8443 \
     --ca-file /tmp/partout-val/tls/ca.crt enroll-token
   ```
4. **Agent (B), mTLS:**
   ```
   PARTOUT_SERVER=<A_IP>:8443 PARTOUT_TOKEN=<new-token> \
   PARTOUT_TLS_CA=/tmp/partout-val/ca.crt \
     /path/to/partout --mode=agent --data-dir=/tmp/partout-val/agent-tls
   ```
   *Expected:* `agent: enrolling with token …` → `agent: enrolled as ag_…` →
   `agent: persisted mTLS material in /tmp/partout-val/agent-tls/tls` (leaf + key)
   → `agent: connected to <A_IP>:8443`.
5. **mTLS enforcement (A):** a **plaintext** client should be **rejected** on the TLS
   port. Sanity: `curl -fs http://<A_IP>:8443/healthz` **fails**; `curl -fsS
   https://127.0.0.1:8443/healthz --cacert /tmp/partout-val/tls/ca.crt` →
   `{"status":"ok"}`.
6. **Run a command (A):** HTTPS again → `--ca-file`:
   ```
   /path/to/partout ctl --server <A_IP>:8443 \
     --ca-file /tmp/partout-val/tls/ca.crt run --selector all -- id
   ```
   → `execution exec_… dispatched` → `succeeded` (runs over the mTLS stream).
7. **Agent restart (B):** restart the agent (no token). *Expected:* reconnects over
   mTLS using the **persisted** leaf/key — no re-enrollment, no new CSR.

**TLS/mTLS result:** ________ (PASS/FAIL — which step, if not)

---

## Report format (paste back)

```
binary:   v0.1.1 (commit 44059a5)
arch:     <amd64/arm64>
server A: <ip / os>
agent  B: <ip / os>
network:  <same-LAN / VPC / internet, any proxy?>
plaintext: PASS/FAIL  (step n: …)
tls/mTLS:  PASS/FAIL  (step n: …)
server-restart reconnect: observed in ~__ s
agent-restart (no re-enroll): PASS/FAIL
notes / errors:
```

---

## Cleanup — remove everything the test touched

```
# on BOTH machines:
pkill -f 'partout --mode='            # stop server + agent
rm -rf /tmp/partout-val               # db, identity, TLS material, tokens
rm /path/to/partout 2>/dev/null || true   # the copied binary
```

Verification that nothing remains:

```
# both machines — expect no output from all three:
pgrep -af partout
ls /tmp/partout-val 2>/dev/null
ss -ltnp | grep partout
```

No other changes are made: no systemd units, users, packages, or config files outside
`/tmp/partout-val` (env vars are per-shell and vanish with the session).

## Security note

Single‑user mode (no RBAC tokens) is fine for a throwaway lab. If you run this over an
untrusted network, use the **TLS variant** only; plaintext is for the controlled test.