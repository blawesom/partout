# Spec — File Root: confining the file surface to a dedicated folder

**Status:** implemented (v0.9.x beta; see §10 for how each open question was
resolved). **Scope:** agent-side file surface (`internal/agent/fs`) + the REST
files API + task `file`/`template` steps + provisioning + uninstall + UI +
server gate.
**Motivation:** today an operator with file permissions can stat/read/write/
perm **any** absolute path the agent user (or sudo) can touch — including
`/etc/*`, dotfiles, and other services' state. The file API should be a
**jailed, unprivileged** surface: one dedicated folder, nothing else.
Everything outside the jail goes through the command surfaces (exec / task
`command` steps), where policy + elevation scope already apply.

---

## 1. Current state (what this changes)

- REST: `GET /api/v1/files/stat|list|download` (viewer), `POST
  /api/v1/files/upload|edit|perm` (operator) — all take an **absolute**
  `path` + `agent_id`.
- Agent: `SafePath` (absolute required, no symlink components, real
  intermediate dirs) + transfer bounds (D3). Uploads stage a temp file in
  the **target's directory**; `EditCAS` is compare-and-swap by sha256;
  `SetPerm` takes mode **and** owner/group (the latter needs root today and
  simply fails as `partout`).
- Server: staged upload bodies wait in `<dbdir>/filestaging/` while parked
  for approval; paths are opaque to the server.
- Elevation slice (shipped): the file surface is **not** elevated — it runs
  as `partout`. This spec makes that the permanent rule.

## 2. The file root

- **Config:** `PARTOUT_FILE_ROOT` (env) / `--file-root` (flag). Agent-side
  only.
- **Default: `/home/partout`** — the agent user's dedicated file space.
  **Hardcoded path, deliberately not derived from the user's home directory:**
  on the standard server/embedded install the `partout` user's home *is*
  `/var/lib/partout`, which contains `partout.db`, the root CA (`tls/`), and
  the server identity — a "user home" default would expose that state to
  the file surface. A fixed `/home/partout` doesn't exist on such hosts,
  gets auto-created empty, and stays safe. (If an operator explicitly sets
  the root onto a state dir, `partout doctor` should warn.)
- **Footprint:** the provisioning install script and the deploy README
  create `/home/partout` (`0750 partout:partout`) alongside the existing
  dirs; `partout uninstall --purge` removes it (it is install footprint —
  operator-uploaded files live there, so the purge output must say so).
- **Startup behavior:** the agent canonicalizes the root (it must be a real
  directory, no symlink). Missing → create `0750` owned by the agent user
  and log it. Uncreatable/unusable → the file surface is **disabled**: every
  file op returns `file root unavailable` (fail closed), other agent
  functions unaffected. The canonical root is recorded as fact
  `partout.file_root` (see §7).
- **The root is host configuration, not a runtime setting.** No API, CLI,
  WebUI action, or admin operation changes it; the only way is editing
  `agent.env` and restarting the unit. It is always visible: in `agent.env`
  and in the `partout.file_root` fact.

## 3. Path semantics

- Request paths are **root-relative**. The API keeps the `path` parameter;
  a leading `/` is stripped and re-based onto the root:
  `nginx.conf` ≡ `/nginx.conf` → `<root>/nginx.conf`.
- **Resolution algorithm** (applied to every op, before anything touches
  disk):
  1. Reject empty paths.
  2. `filepath.Clean`; reject any remaining `..` component (escape attempt).
  3. Join onto the canonical root; the result must equal or be under the
     canonical root (string prefix on the resolved path — belt and braces).
  4. Walk the joined path exactly as `SafePath` does today (Lstat each
     component): no symlink components at all, intermediate components must
     be real directories, final component may be missing (upload target) but
     must not be a symlink if it exists.
  5. Re-check the fully resolved final path is still under the canonical
     root (bind mounts are out of scope; see §9).
- **Symlinks inside the jail: forbidden entirely** (strict rule, same
  posture as current `SafePath`). Consequence: you cannot expose an outside
  tree by symlinking it into the jail. To expose a tree, point
  `PARTOUT_FILE_ROOT` at it (or its parent), or bind-mount/copy it into the
  jail. Strictness beats convenience here — a symlink that resolves outside
  is precisely the escape class this feature exists to block.
- **Failure mode:** any step that fails → op rejected with
  `path escapes file root: <reason>`; nothing is created or modified; an
  audit row is written (§8). Rejection is **not** policy-exempt — it is a
  hard agent-side invariant, checked after the policy/guardrail chain, like
  the guardrail re-check: policy can deny more, never less.

### The no-escape invariant (all roles, all interfaces)

**Role gates *what* file operations may happen; the root gates *where*. No
role, flag, env var, API parameter, CLI option, WebUI action, or MCP tool
touches the *where* — not for admin, not for anyone.** There is no
`--absolute` flag, no `PARTOUT_ALLOW_*` escape hatch, no privileged mode:
the `path` parameter of the files API means *only* "path inside the file
root", on every surface. If a workflow needs a file outside the root, that
is a **command** (exec / task `command` step) — a different surface with its
own visible controls (policy deny-list, approvals, sudoers scope). This is
what makes the file API cheap to use (viewer reads, operator writes) while
being safe by construction. Scope of the guarantee: the *Partout
interfaces* — host-level root/sudo can read `/home/partout` like anything
else on the machine; the invariant is that no Partout user of any role can
make the agent touch a path outside the root through any Partout surface.

## 4. Per-operation behavior (all inside the jail)

| Op | Behavior change |
|---|---|
| `stat` / `list` / `download` | resolve against root; bounds unchanged (D3 sizes, list cap) |
| `upload` (chunked) | target + temp file (`.partout-tmp-*`) both inside the jail — already same-dir as target, so the temp inherits the confinement |
| `edit` (CAS by sha256) | compare against resolved path; atomic write = temp + rename **within the jail** (same filesystem — guaranteed, since temp sits beside target) |
| `perm` | **mode changes only.** Inside the jail the agent user owns everything, so mode changes work unprivileged. `owner`/`group` parameters are rejected with a clear error (`ownership changes are not allowed inside the file root`) — they were root-only and meaningless here. This resolves the SetPerm-privilege question: the file surface needs **no** elevation at all |
| delete | (not in the current surface; if added later, same resolution) |

Transfer bounds, chunking, and the approval-park flow (server-side
`filestaging/`) are unchanged.

## 5. Interaction with elevation — a hard rule

**The file surface is never elevated.** Jailed ops run as the agent user;
the jail is owned by the agent user, so everything inside works
unprivileged. If a workflow needs a file outside the jail, that is a
**command** (dispatched exec or a task `command` step) — where the policy
deny-list, approvals, and the sudoers scope are the controls. This also
means elevation can never be used to bypass the jail: `sudo -n` is simply
not in the file surface's vocabulary.

## 6. Task `file` / `template` steps — in scope

They are file writes with the same exposure, so they resolve against the
same root (root-relative `path`, same algorithm, same rejection/audit).
Documented escape hatch for writing elsewhere: use a `command` step
(`tee`, `install -m`, …) — explicit shell, policy-gated, elevation-scoped.
`assert` steps that read arbitrary paths are read-only and stay as-is
(flagged in §10 as a follow-up candidate).

## 7. Server & UI

- Server stays path-opaque (enforcement is agent-side, authoritative —
  same principle as the guardrail re-check). Fast feedback only: the REST
  layer rejects obviously absolute/escaping paths with 400 before dispatch.
- Agent reports `partout.file_root` (canonical) in facts. UI files browser
  shows the root as a prefix/banner: `paths are relative to
  /var/lib/partout/agent/files on ag_…`; path inputs validate client-side.
- Agents whose facts lack `file_root` (pre-upgrade) are marked **legacy
  file surface (absolute paths)** in the UI. Optional server toggle
  `PARTOUT_REQUIRE_FILE_ROOT` (default `false` in beta; intended `true` at
  1.0) rejects file ops to legacy agents.
- **Fail-closed ≠ legacy.** An agent ≥0.9.5 whose root could not be
  prepared reports `partout.file_root_error` (the reason, e.g. `fs: create
  file root /home/partout: permission denied`). The UI then shows the real
  diagnosis — root unavailable, remedy inline (`mkdir -p` + `chown`, or
  `PARTOUT_FILE_ROOT`) — instead of the legacy "upgrade the agent"
  advice, and a `PARTOUT_REQUIRE_FILE_ROOT` refusal quotes the agent's own
  reason. The fact is agent-level **static state**: it is re-applied over
  every facts collection (the first facts batch used to replace the
  factset wholesale and wipe it, making every 0.9.5+ agent look legacy).
  `partout doctor` (agent/embedded mode) checks the root read-only and
  prints the same remedy.

## 8. Audit

- New denial record: `file.path_escape` — actor, agent, requested path,
  reason (traversal / symlink / outside root / root unavailable).
- Successful ops are audited as today, with the **resolved** absolute path
  (the operator sees exactly what happened where).

## 9. Threat model — what this does and does not prevent

**Prevents:** the file API (directly or via a compromised/over-broad policy
+ approval flow) writing, reading, or re-perming outside the dedicated
folder; path-traversal and symlink escapes via the file API; owner/group
manipulation through `perm`.

**Does not prevent (by design):** a dispatched **command** reading/writing
anything its user (+ sudoers scope) allows — that surface is controlled by
policy + elevation, not by this jail; host-level attacks (an admin with
shell access can `mv` the jail); bind mounts under the jail (operator
action, out of scope — documented).

## 10. Open questions — resolved at implementation

1. **Mixed-version fleets** — done: `PARTOUT_REQUIRE_FILE_ROOT` ships, defaults
   **off**; the Files page shows a root banner (or a legacy warning when no
   root fact is reported). Flip the toggle on after a fleet-wide upgrade.
2. **Task `assert` reads** — left read-only-absolute (harmless: read-only,
   and `assert` is an operator-confirmed check, not a data-exfil surface).
   Revisit at 1.0 if the surface widens.
3. **`perm` API shape** — keep-and-reject: `owner`/`group` are accepted in the
   payload but rejected with a clear error (mode-only is the only permitted
   change). Drop the fields at 1.0.
4. **Provisioner** — the install script creates `/home/partout` (0750,
   owned by `partout`) on every provisioned host. `ctl provision --file-root`
   is **deferred**: custom roots are a per-host `agent.env` edit today; add
   the flag when operators need non-default roots at enroll time.

## 11. Acceptance criteria (for the implementation)

- [x] Every file op with a path that resolves outside the root is rejected
      (unit + e2e: `..`, absolute, symlink inside jail, symlink→outside,
      missing-root, non-dir intermediate).
- [x] Rejection writes `file.path_escape` audit and modifies nothing
      (no temp files left behind).
- [x] Upload/edit temp files and renames stay inside the jail; edit is
      atomic (no partial writes observable).
- [x] `perm` with owner/group is rejected; mode-only succeeds as `partout`
      (no elevation involved — the file surface never elevates).
- [x] Elevation enabled (`PARTOUT_ELEVATE=sudo`): file surface behavior
      identical to non-elevated (no `sudo` in the file path).
- [x] Task `file`/`template` steps obey the same root; writing outside via
      them fails closed; via a `command` step still works (elevation-scoped).
- [x] `partout.file_root` fact present; Files page shows the root banner +
      legacy warning; `PARTOUT_FILE_ROOT` + `--file-root` honored; default is
      `/home/partout` (hardcoded — *not* the user's home) and is auto-created
      `0750`.
- [x] No-escape invariant: no flag/env/parameter on any surface (REST, CLI,
      WebUI, MCP) admits an absolute path or disables the jail; the resolver
      strips and jails every path; admin-token escape attempts are rejected
      and audited.
- [x] `SafePath`'s existing guarantees (no symlink components, real dirs,
      bounds) still hold inside the jail (regression tests).

## 12. Compatibility note

Pre-1.0 beta → breaking change to the files API's path semantics
(absolute → root-relative), acceptable under the beta status line
("occasional breaking change before 1.0"). Call it out in the changelog,
operations.md (files section), and the UI banner for one release cycle.
