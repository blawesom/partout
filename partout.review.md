# Partout — Review: spec alignment, onboarding & first-use experience

**Date:** 2026-11-07 · **Revision reviewed:** `2f0d754` (tags up to `v0.9.18`)
**Trigger:** user feedback — *"they don't know how to onboard their first nodes and
propagate their first commands easily. Either the enrollment is unclear, or rights
management does not allow usage at onboarding."*

## Method

- Built HEAD (`golang:1.26` container, `CGO_ENABLED=0`) and walked the documented paths
  as a new user would.
- **Ran:** `partout --help` / `help` / `doctor` / `ctl`; the embedded demo; a plaintext
  server + a second manually enrolled agent; a TLS server + the agent recipe printed by
  `partout ctl enroll-token`; `ctl run`, `ctl audit`; `go vet ./...` + `go test ./...`.
- **Read, not run:** the web UI Add-host dialog (plaintext branch), the SSH provisioning
  wizard.
- Checked PRD claims against the code by grep.

---

## Verdict

User feedback is accurate on **both** counts:

1. **Enrollment** — the default server posture (plaintext) hides the only good recipe
   (the one-line installer), and the fallback the UI shows is broken in three
   independent ways. The CLI's own printed recipe is broken on TLS servers and burns the
   one-time token.
2. **Rights** — elevation is **opt-in and unchecked by default** in every onboarding
   path, so the first realistic commands (`systemctl`, `apt`) fail with raw OS
   permission errors, and the Execute page never says why.

**Ruled out:** the seeded policy preset (narrow: `rm -rf /`, disk wipe, auth-file
tamper → deny; reboot / EOL upgrade → approval) and RBAC (the bootstrap `admin` holds
every role) are not what blocks first use.

The core loop itself works: a connected host runs `uptime` via `ctl run`, output streams
back, the audit log records it.

---

## 1. Onboarding blockers (from the user feedback)

### 1.1 `ctl enroll-token` prints a recipe that fails on TLS servers — **critical**

`cmd/partout/ctl.go:609-610` prints:

```
PARTOUT_SERVER=https://host:8443 PARTOUT_TOKEN=par_enr_… partout --mode=agent
```

`strings.TrimPrefix(c.base, "http://")` leaves `https://` in place, and no CA is
mentioned. Reproduced:

| Attempt | Result |
|---|---|
| Hint verbatim | `x509: certificate signed by unknown authority` (enroll fails) |
| Hint + `PARTOUT_TLS_CA=ca.crt` | **enrollment succeeds and burns the token**, then the stream loops forever: `invalid target address https://127.0.0.1:18444 … too many colons in address` |
| Fresh retry, correct `host:port` + CA | `server returned 401` (token already consumed) |
| Retry in the **same** data-dir, correct `host:port` | connects — recovery exists, but nothing tells the user |

The README's step-3 recipe is correct; the tool contradicts its own docs. Enrollment
(HTTP client) accepts a scheme the gRPC stream rejects — the address is validated
inconsistently, and only after the token is spent.

### 1.2 Plaintext Add-host dialog never yields a working command — **critical**

Plaintext is the default, so this is the path most first users hit
(`internal/api/webui/app.js:155-226`, `:2714-2742`):

- The one-line installer (persistent service, elevation wiring) is **HTTPS-only**.
- The "download the binary" command is **never shown on a release build**:
  `ahIsRelease()` tests `/^v\d+\.\d+/`, but releases stamp the version without the `v`
  (`scripts/release-github.sh:36`, `VER="${TAG#v}"` → `/api/v1/version` returns
  `0.9.18`). The user gets "download from the releases page" instead.
- Even with the regex fixed, the URL it builds would 404: it uses the bare version as
  the tag path (`releases/download/0.9.18/…`) while releases are created under the
  `v`-prefixed tag (`release-github.sh:141`).
- The run step says `partout --mode=agent`, but the tarball extracts to
  `partout_linux_<arch>/partout` (`release-github.sh:43-47`) — not on `PATH`, so
  "command not found".
- If it does run, it is **foreground only** (dies with the SSH session), runs as the
  login user, has no elevation, and the Files surface is disabled (cannot create
  `/home/partout`; reproduced on both the embedded and the manual agent).
- The server already serves a per-token agent binary at
  `GET /api/v1/join/{token}/binary` (`internal/api/join.go:57`); this path ignores it.

### 1.3 Elevation is off by default everywhere — **high**

- Add-host "Run on the host": `ahElevate: false` (`app.js:2554`).
- Add-host "Onboard over SSH": `provWiz.elevate: false` (`app.js:2560`).
- Agent flag default: `--elevate none`.
- Meanwhile the README status line advertises "broad sudo as the friction-free
  default". "Default" refers to the policy pre-selected *once you tick the box*, which
  first users don't do.

### 1.4 Execute doesn't explain privilege failures — **high**

Reproduced in the demo: `ctl run --selector all -- systemctl restart cron` →
`Access denied as the requested operation requires interactive authentication`. The
"Elevation is off on this host → Enable elevation…" affordance exists only on Updates
(`app.js:1343`) and host attention items (`app.js:3563`), not on Execute or run detail.

Note the good news: ad-hoc Execute already goes through `runElevated`
(`internal/agent/agent.go:1416`), so once elevation is on, the same command works. The
fix is a default + a hint, not a new code path.

### 1.5 SSH wizard likely unusable after the installer — **unverified**

The wizard uses the **server's own** `~/.ssh`. `doctor` reported no identity key,
including for the installer's service user (`/var/lib/partout/.ssh`). Not tested end to
end.

### 1.6 Root cause: plaintext on all interfaces is the default

Every first user is routed into §1.2. See §2.3.

---

## 2. General onboarding & CLI usability

### 2.1 Any unknown argument starts a server — **critical**

`cmd/partout/main.go:140` parses flags but never checks `fs.NArg()`. `partout help`,
`partout version`, or any typo boots a **plaintext server on all interfaces** and writes
`partout.db`, `admin_password.txt` and `identity/` into the current directory.
Fix: after `Parse`, `NArg() > 0` → print usage, exit 2; pin in
`cmd/partout/usage_contract_test.go`.

### 2.2 Discoverability

- `partout --help` lists flags only — none of the subcommands (`ctl`, `doctor`,
  `update`, `uninstall`, `selftest`).
- The `-mode` help string says `server|agent|embedded` (`main.go:121`) though `mcp` is
  accepted (`main.go:225`).
- Bare `partout ctl` errors with `--server (or PARTOUT_SERVER) is required` instead of
  printing the (good) `ctl help`.

### 2.3 Default security posture vs messaging

- Default: all interfaces + plaintext. `doctor` reports "3 warning(s), no failures —
  ready" and exits 0.
- README callout (line 111): "Plain HTTP is the default — and loopback-only is the safe
  default", followed by "A fresh server binds **all interfaces**" — contradictory
  phrasing.
- The embedded-demo snippet comments "loopback + plaintext is the local-dev posture",
  but the command it shows binds all interfaces.

Recommendation: bind loopback unless TLS is on (or make `doctor` fail on
all-interfaces + plaintext).

### 2.4 Embedded demo rough edges

- Startup banner step 1 says "Onboard a host" when the embedded host is already connected.
- Files disabled for a non-root user (see §1.2); the UI's fix-it text references a
  `partout` user and `/etc/partout/agent.env`, which don't apply to a demo.
- No elevation (§1.3–1.4).

### 2.5 README as the entry point

247 lines; opens with the installer bundle (requires a published release, `<version>`
placeholder ×4) and a source build before reaching the "fastest path". Internal
contradictions:

- Status says **v0.9.16**; latest tag is **v0.9.18** (PRD header too).
- Line 6: audit hash chain shipped; line 20: hash chain is "a documented post-v1
  enhancement".
- Line 111: the loopback callout (§2.3).
- Line 183: Docker is "maybe-future", while `deploy/docker/` ships a Dockerfile and
  compose file and the status line lists "a minimal Docker path".

### 2.6 Minor

- A fresh fleet page can stack up to three onboarding cards above the host list
  (`app.js:713-760`: secure-this-server, finish setup, get started / first host).
- `doctor` prints `ok   outbound OSV.dev   404 Not Found` — correct (reachability), but
  reads as a failure.

---

## 3. Spec ↔ code alignment

| PRD statement | Reality |
|---|---|
| §1, §2.2, §10.3: observe layer covers **containers, endpoints, heartbeats**, status page | Not implemented. Shipped observe = services, configs, TLS certs. No endpoint probes, container facts, heartbeat monitors or status page in the code. |
| Principle 6: runtime-agnostic, auto-detects **Docker / K8s node** | Not implemented. |
| Principle 2: optional **PostgreSQL** | R9 says Postgres is post-v1; principle not updated. |
| **Decision 3**: per-command sudoers default; `--elevate=none\|sudoers\|sudo` | Shipped: broad-sudo tier as the elevation-policy default, `--elevate none\|sudo` only. Decision text never updated. |
| Principle 9: agent runs unprivileged by default | Literally true (elevation off), but in tension with the shipped "broad sudo default" messaging — and §1.3 shows the ambiguity hurts users. |
| **Decision 5**: no hash chain in v1 (`PRD.md:863`) | Shipped and promoted to a 1.0 gate (`docs/roadmap.md:707`); `ctl audit verify` exists. |

Recommendation: either cut or explicitly mark as **not shipped** every unimplemented
promise; update Decisions 3 and 5 in place (with a dated amendment) rather than leaving
the decision log stale.

---

## 4. Documentation consistency

- ~7.6k lines of docs, including a 958-line PRD; release status is restated in the
  README, PRD header, roadmap and several docs, and the copies drift.
- `docs/ux-improvements.md` header says "nothing in this document is implemented yet"
  above rows marked ✅ shipped.
- Recommendation: one status source (`docs/roadmap.md`) that the README and PRD link to
  rather than restate; trim the README to the embedded demo + a link to
  `docs/getting-started.md`.

---

## 5. Tests

- `go vet ./...`: clean.
- `go test ./...`: all packages pass except three, in the `golang:1.26` container:
  - `cmd/partout`: `TestUninstallExecuteOrderAndEffects`,
    `TestUninstallExecuteAbortsOnStopFailure`
  - `internal/agent/elevate`: `TestRenderSudoersBareCommand`

  These look environment-dependent (the image has no `systemctl` / `reboot` to
  resolve). **Not verified on a real host**; if confirmed, make them hermetic.

---

## 6. What works well — keep it

- The startup banner: UI URL, password source, TLS posture, next steps.
- `doctor`'s framing (exactly what would stop a start).
- `ctl enroll-token` printing the next command (once it prints the right one).
- `ctl run` per-host output; structured audit.
- The UI's connect watcher (✓ Connected / 90 s troubleshooting), "Run your first
  command" nudge (prefill, never auto-run), and the Files disabled-state explanation.
- Narrow, sensible policy preset.

---

## 7. Recommended fixes, in unblock order

| # | Fix | Where | Effort |
|---|---|---|---|
| 1 | Pre-check "enable elevation" with `default-broad` in both Add-host tabs | `app.js:2554`, `:2560` | hours |
| 2 | Fix the enroll hint: `host:port`, add `PARTOUT_TLS_CA=ca.crt` on TLS, `./partout`; agent rejects a scheme in `PARTOUT_SERVER` **before** enrolling | `ctl.go:609`, `internal/config` | hours |
| 3 | Plaintext Add-host path: download from `/api/v1/join/{token}/binary`, use `./partout`, point to `scripts/install-agent.sh` for a persistent install | `app.js:2714-2742` | ½ day |
| 4 | Execute / run detail: on a permission failure on a host whose elevation mode ≠ `sudo`, show the existing "Enable elevation…" affordance | `app.js` (reuse `openElevBoot`) | ½ day |
| 5 | `ahIsRelease` accepts bare semver; download URL uses the `v`-prefixed tag | `app.js:2735-2741` | hours |
| 6 | Reject leftover positional args; list subcommands in `--help`; bare `ctl` prints help; add `mcp` to `-mode` help | `main.go:121-140`, `ctl.go` | hours |
| 7 | Default bind loopback unless TLS is on (or `doctor` fails on all-ifaces + plaintext) | `internal/config`, `doctor.go` | ½ day + docs |
| 8 | Embedded demo: mode-aware banner; file root under the data dir when not root | `main.go`, agent fs | ½ day |
| 9 | PRD: mark unshipped scope; amend Decisions 3 and 5; single status source; trim README | `PRD.md`, `README.md`, docs | 1 day |
