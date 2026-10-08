# Proposal — Setup & privilege-management UX (for review; nothing implemented)

> **Status: IMPLEMENTED (phases 1–3, v0.9.14 cycle).** Phase 1 (P3.1 run-row
> elevation reason, E3 posture card, P4 elevation_drift alert), phase 2
> (E1 one-line join, E2 control-plane binaries, P1 one-command elevation
> bootstrap), and phase 3's P2 (signed policy propagation) + P3.2
> (`elevation explain`) are in. **Remaining from phase 3:** P3.3 (structured
> policy editor) and P3.4 (fleet-aware policy generator) — UI work, next
> cycle. The text below is the reviewed proposal, kept as the design record.
>
> Design rationale lives in [architecture.md](architecture.md); day-2 operations in
> [operations.md](operations.md); deployment topologies in [deployment.md](deployment.md).
> The [README](../README.md) is a short overview (objectives, problem, architecture, deploy,
> UI, CLI).

---

## Part 1 — First-node enrollment

### E1 · One-line join: the server serves the bootstrap script

**Problem.** Path A ("run on the host") is 3 copy-paste steps that still leave a
*foreground* agent: no systemd unit, no persistence across reboot, no elevation. The
real install path (`scripts/install-agent.sh`, which already handles the M8.1 layout,
env file, unit, and elevation wiring) lives in the git repo — the user on the host has
no access to it, so they hand-assemble its steps. The binary download step is a
GitHub-arch-translating `sed` incantation that renders as *nothing* on dev builds.

**Proposal.** A token-gated endpoint on the control plane serves a personalized,
deterministic bootstrap script:

```
curl -fsSL https://srv:8443/join/<one-time-token> | sudo bash
```

The script (rendered server-side, per token):

- embeds `PARTOUT_SERVER`, the TLS mode, and — on HTTPS servers — the root CA **inline**
  (written to `/etc/partout/ca.crt`; no separate CA step);
- detects arch (`uname -m`) and fetches the matching agent binary **from the control
  plane** (see E2), verifies its sha256 (embedded in the script);
- runs the existing `install-agent.sh` logic: M8.1 layout (`/var/lib/partout/bin`,
  update guard, `/usr/local/bin` symlink), `agent.env`, systemd unit, enable + start;
- optionally wires elevation up front (the minting operator picks a stored policy —
  default `default-baseline` — the same choice provisioning offers today);
- is idempotent and `--dry-run`-able.

The Add-host dialog leads with the one-liner (one copy button + a "view the script
first" link — we should *encourage* inspection, not just pipe-to-bash); the current
3-step recipe collapses into an "Advanced / manual" disclosure. The existing
connection-watch (✓ Connected / troubleshooting hints) is unchanged.

**Why it's safe.** The script is served over the same TLS as the UI; the enrollment
token gates the endpoint (single-use, 15 min TTL, exactly like today's token); the
script's payload (server addr, CA, sha256, policy) is derived server-side so nothing
host-side has to be trusted. On a plaintext (`PARTOUT_TLS` off) server we do **not**
offer `| bash` (mid-flight tampering of a root-running script is unacceptable) — the
dialog shows the copy-out recipe instead, as today. One command run as root is the
same trust the operator already spends with path B's `sudo bash -s` install step or
any `curl | sudo bash` installer; the difference is fewer steps and an inspectable,
deterministic artifact.

**Effort.** M — endpoint + script renderer (mostly re-arranging `install-agent.sh` into
a template the server can stamp), dialog change, tests (fake-host integration like the
provisioner's).

**Open questions.**
- (a) Should the one-time token authorize `/join/<token>` only, or also the binary
  download endpoint (E2)? Propose: same token, both — the token already only grants
  "become a fleet member."
- (b) Ship the CA inline vs. keeping the separate `ca.crt` step? Propose inline —
  one less file to place; the script can pin it by fingerprint in its comments.

### E2 · The control plane serves agent binaries (reuse the M8.1 release store)

**Problem.** The download step depends on GitHub releases with a fragile arch
translation, breaks on dev builds, and adds a third party to the trust path of day 1.

**Proposal.** `GET /join/<token>/binary?arch=<a>` (or an equivalent release-store
route) serves the agent binary:
- the M8.1 **release store already holds signed agent release tarballs** — serve the
  matching arch from there when present;
- the server can also serve **its own executable** for same-arch hosts (it is the same
  static binary; sha256-announced in the script);
- GitHub remains the fallback (and the source for populating the store).

This also fixes provisioning's transfer step for air-gapped / GitHub-less
environments, and makes dev builds (no release assets) fully onboardable.

**Why it's safe.** Same gating as E1; the release store is already sha256 + Ed25519
verified (M8.1) — the join route verifies before serving, exactly as the rollout path
does. Serving the server's own binary is integrity-equivalent (it's the running
process's file).

**Effort.** S–M (a route + store lookup + tests).

### E3 · Post-connect posture card (the "now what?" moment)

**Problem.** After the host connects, the UI's guidance stops. The three day-1 gotchas
(elevation off → package applies will fail; no service labels → observe sees nothing;
file-root note) are documented but not *surfaced where the user is looking*.

**Proposal.** When a host connects (and on the host page while posture is incomplete),
render a dismissible **first-boot checklist** card driven by facts the server already
has: elevation posture (`partout.elevation` fact: off / policy hash / mode), service
labels empty, observe freshness. Each item links to its one-command fix (E1's elevation
variant for the elevation item, P1 below), not to a docs page. The existing Updates
pre-apply banner already does this for one case — generalize it.

**Effort.** S (UI card + fact reads; no server change).

### E4 (optional) · `partout setup` first-run wizard

A guided `partout setup` on the server: TLS decision (with the plaintext warning),
admin password, first host (prints the E1 one-liner), elevation choice. `doctor` +
the startup next-steps block already cover most of this; only worth it if we keep
hearing "where do I start" after E1 lands. **Defer.**

---

## Part 2 — Privilege (elevation) management

### P1 · One-line elevation bootstrap for hosts that are already enrolled

**Problem.** For a host provisioned *without* elevation (or enrolled via path A), the
documented enable path is six hand-steps with three known traps: install the policy
file, `sudo /usr/local/bin/partout ctl elevation install-sudoers` (full path —
secure_path excludes `/usr/local/bin` on RHEL), edit `agent.env`, remove
`NoNewPrivileges=true` from the unit, `daemon-reload`, restart. This is the single
biggest "hard to set up correctly" complaint.

**Proposal.** The host page (and Elevation fleet-posture table) gets **"Enable
elevation…"**, which mints a short-TTL, single-use, host-scoped token and shows:

```
curl -fsSL https://srv:8443/elevate/<token> | sudo bash
```

The script carries the chosen stored policy (inline, canonical JSON + its sha256),
renders the sudoers drop-in **on the host** using the binary already installed there
(`/usr/local/bin/partout ctl elevation install-sudoers` — the script uses the full
path, dodging the secure_path trap), fixes `agent.env` + the unit, restarts, and runs
`elevation check` as verification. The UI watches the `partout.elevation` fact flip
and confirms. The existing fallback (SSH provisioning with `--elevate`, or config
management) remains for fleets.

**Why it's safe.** This is honest about the chicken-and-egg: installing a sudoers file
*requires root on the host*, and the unprivileged agent must not be able to grant
itself privilege (that's PRD Decision 3's whole point). So the flow keeps the
operator's one privileged action — but makes it one pasted command instead of six,
with the generated artifact inspectable. Same TLS-only rule as E1; the token is
host-scoped so it can't be used to enroll anything; the policy served is the stored,
hash-canonicalized one the operator just reviewed in the dialog.

**Effort.** S–M (mirror of E1's mechanism: endpoint + script render + fact watch; the
render-on-host machinery already exists in `ctl elevation install-sudoers`).

### P2 · Self-managed policy propagation — the agent updates its own wall, under a signed grant

**Problem.** The policy store is central, but *"updating a stored policy does NOT
touch already-provisioned hosts"* — the wall is host-owned, so every policy change
means re-provisioning in join mode or shipping files with config management. For a
tool whose pitch is "one control plane," policy drift by default feels broken to
users, and `elevation check` (drift *detection*) is a consolation prize, not a fix.

**Proposal.** Make the default-baseline (and every generated) policy include one narrow
**self-management grant**, so a host that already has elevation can accept centrally
pushed policy updates:

- the sudoers wall grants exactly:
  `partout ctl elevation apply-signed <path>` — one command, exact-args match, no
  wildcards, plus `systemctl restart partout-*` (already granted by baseline);
- `apply-signed` takes a **server-signed bundle**: canonical policy JSON + target
  host ID + version, signed with the server's Ed25519 key (the M8.1 signing
  infrastructure — same key ceremony, existing release-store code paths). The agent
  verifies the signature against the server key it already trusts from enrollment
  before touching anything; a compromised unprivileged `partout` user cannot forge a
  policy;
- `apply-signed` renders to a temp file, `visudo -cf`-checks it, atomically swaps the
  drop-in, restarts the agent, and the restarted agent re-verifies (`elevation check`)
  as its boot self-test — the M8.1 self-swap rollback pattern applied to sudoers;
- the **Elevation page gains "Push policy to fleet"**: a governed action (admin role,
  server-side policy engine, `require_approval`-able like every other write), audited,
  with per-host results and the existing hash-match posture table showing convergence.

Fail-closed is preserved end-to-end: nothing elevates that the *host's current* wall
doesn't allow; the wall only ever widens via a signed, audited, human-gated push; and
a host can stay pinned forever by simply not including the self-grant in its policy
(the strict-locked-down fleet story is unchanged).

**Effort.** M–L (signing reuse, `apply-signed` command, governed action + UI, tests
including the rollback path). This is the structural fix; worth doing after P1/P3
prove the vocabulary.

**Open questions.**
- (a) Include the self-grant in `default-baseline` by default, or opt-in per policy?
  Propose: include, clearly labeled in the policy viewer — it is the difference between
  "central control plane" and "central document archive."
- (b) Scope the signature to (host, policy) or (fleet, policy)? Propose (fleet,
  policy) with per-host opt-out, so one push fans out; host-scoped pins remain
  possible.

### P3 · Authoring & explainability — make the policy legible

**Problem.** Policy authoring is raw JSON with subtle semantics: rules are exact
arg-sequence globs, `path.Match` globs never cross `/`, a bare `{"allow":"reboot"}`
means *zero arguments*. The baseline itself encodes exact internal incantations
(`apt-get -o Dpkg::Options::=--force-confdef …`) that had to be field-discovered —
users cannot derive them from the docs, and there is no way to ask "why didn't my
command elevate?" other than reading agent logs.

**Proposal** (four independent pieces, in priority order):

1. **Record the elevation decision on every run.** The agent already knows why a
   command ran unprivileged (no policy / no matching rule / `PARTOUT_ELEVATE=none` /
   legacy mode). Put that reason on the run row and show it in Execute/Audit as a
   badge + tooltip ("ran unprivileged: no rule matched `dnf upgrade` — see Elevation").
   *This is the single highest-value line item in the whole proposal* — it converts the
   most common silent failure into a one-glance answer. Effort: S.
2. **`elevation explain` (CLI + API).** Given a policy and a command line, show which
   rule matches and what sudoers it renders — or precisely why nothing matched. Backs
   a "test against host X's installed policy" button in the policy editor. Effort: S–M
   (the matcher already exists; this is a surface for it).
3. **Structured policy editor.** The elevation page form becomes rule-builder rows
   (command, verbs/units, args, files, env) with validation and a raw-JSON toggle for
   power users; plus 2–3 more seeded profiles (web tier / database / minimal) derived
   from `default-baseline` by trimming. Effort: M (UI-heavy, no server semantics
   change).
4. **Fleet-aware policy generator.** From observed facts the server already holds
   (labeled services, watched config paths, cert paths, package-manager family),
   propose a minimal policy — crucially including the **exact command shapes Partout
   itself invokes** for those targets (package manager incantations, validator
   commands), which today must be copied out of docs or field-discovered. Present as a
   reviewable diff against the stored policy, not an auto-apply. Effort: M.

### P4 · `elevation_drift` fleet alert

The posture table already matches installed hashes against the store; make
non-matching a proper alert rule kind (default preset, editable like
`default-update-drift`) so drift pages the operator instead of waiting for a visit to
the Elevation page. Effort: S.

---

## What this proposal deliberately does NOT change

- The agent stays unprivileged by default; elevation remains opt-in and fail-closed
  (PRD Decision 3). No silent auto-enable, ever.
- Installing the *first* sudoers file still requires a privileged action on the host
  (one pasted command via P1, or provisioning's root install). The unprivileged agent
  never bootstraps its own privilege.
- The deny-list policy engine, approvals, and audit coverage are untouched — every new
  write surface (join script serving, elevation push) is a governed, audited action
  with RBAC, and `require_approval` applies as usual.
- No new trust roots: E1/E2 reuse the enrollment token; P2 reuses the M8.1 Ed25519
  release-signing key.

## Suggested sequencing

| Phase | Items | Outcome |
|---|---|---|
| 1 (quick wins) | P3.1 (run-row elevation reason), E3, P4 | The confusion becomes visible; no new surfaces |
| 2 (the onboarding fix) | E1 + E2, P1 | First node = one pasted command, persistent, elevation-able |
| 3 (structural) | P2, P3.2–3.4 | Central policy that actually propagates; legible authoring |

Estimated total: roughly one minor-version cycle (a "v0.9.14: setup & privilege UX"
field-verification pass), with phase 1 shippable independently and early.
