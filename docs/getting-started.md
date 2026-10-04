# Partout — Getting started (5 minutes)

> The guided first-run walkthrough: install → first host → first command → verify in the
> audit log. Reference documentation lives in [PRD.md](../PRD.md) (product),
> [docs/architecture.md](architecture.md) (design), [docs/deployment.md](deployment.md)
> (topologies, config), and [docs/operations.md](operations.md) (day-2).

## 0. What you need

- A Linux box for the server (any distro; systemd optional but recommended).
- Optionally: a second Linux host to manage, and SSH from the server box to it.
- No database, no queue, no Node — everything ships in one static binary.

Grab the binary from the
[latest release](https://github.com/blawesom/partout/releases)
(`partout_<version>_linux_<arch>.tar.gz`, SHA-256SUMS included), or build it:

```bash
go build -o partout ./cmd/partout
```

## 1. Start the server

**Pre-flight first** — it reports exactly what would stop a start (port in use,
unwritable DB, TLS posture, outbound CVE/EOL reachability, the SSH key provisioning
would use, and whether fleet provisioning can work at all: a loopback-only bind or
an unresolvable `PARTOUT_SERVER_HOST` would doom every run):

```bash
./partout doctor
```

> **Plain HTTP is the default.** A fresh server binds all interfaces without TLS, so
> the login password and session tokens cross the network in cleartext the moment you
> reach it from another machine. `doctor` warns about exactly this; the login page and
> the UI warn too. For anything beyond this machine, either:
>
> - `PARTOUT_TLS=on` — bootstraps a local root CA; the server serves HTTPS and the
>   agent stream gets mTLS (no per-host cert work), **or**
> - `PARTOUT_ADDR=127.0.0.1` behind your own TLS-terminating proxy
>   (Caddy/nginx/HAProxy patterns: [deployment.md](deployment.md) §1.3).

**Fastest path — one-process demo** (server + a co-located agent; the fleet is
populated the moment you open the UI):

```bash
PARTOUT_MODE=embedded PARTOUT_ADMIN_PASSWORD='change-me-123' ./partout
# loopback + plaintext is the local-dev posture; add PARTOUT_TLS=on to try HTTPS
```

**Real server** (TLS on from the start — recommended for anything reachable):

```bash
PARTOUT_TLS=on PARTOUT_ADMIN_PASSWORD='change-me-123' \
  PARTOUT_TOKEN_ADMIN='cli-admin-token' ./partout
```

The startup log ends with a **next-steps block**: the UI URL, where the admin password
came from (`PARTOUT_ADMIN_PASSWORD`, or the generated `admin_password.txt` next to the
database — rotate it and delete the file), the TLS posture, and the three steps below.
If you did not set a password, sign in as `admin` with the one from that file.

## 2. Onboard your first host

Open the UI (**Fleet → + Add host**) — two paths, pick by how you reach the host:

**A · Run on the host** (you can shell into it): mint a one-time token and follow the
three-step recipe the dialog builds for you —
1. download the binary onto the host (exact `curl`+`tar` for the release asset),
2. *(TLS servers)* download `ca.crt` and place it next to the command,
3. run the agent one-liner (`PARTOUT_SERVER=… PARTOUT_TLS_CA=ca.crt PARTOUT_TOKEN=par_enr_… partout --mode=agent`).

The dialog watches for the host and flips to **✓ Connected** when it appears; if
nothing connects within 90 s it tells you what to check (token validity,
host→server reachability, the CA, agent logs).

**B · Onboard over SSH** (admin; the server's own `~/.ssh` reaches the host): the
guided wizard walks target → plan (with a live SSH-key readiness check) → the five
steps (`connect → preflight → transfer → install → wait-enroll`), streaming live. A new
host key pauses the run until you confirm the fingerprint — no silent trust.
`fresh` mode wipes any existing partout agent on the host (clean slate); `join` updates
in place, identity preserved. Check **Enable elevation** and pick a policy (the seeded
`default-baseline` is the day-1 profile) so package updates, service control and
reboots work from the first minute — the policy, the sudoers drop-in rendered from it,
and `PARTOUT_ELEVATE=sudo` are all wired through the run's root install; no extra SSH.
The CLI equivalent:

```bash
partout ctl provision new --host deploy@web01 --elevate --service-labels fail2ban,sshd
```

Bringing up **hosts 2..N**? The Provision page takes a batch — one `user@host` per
line, each becoming its own run.

## 3. Run your first command

When the first host connects, the Fleet page offers **Run your first command** — it
prefills Execute with a harmless `uptime` scoped to the new host (you press Run;
nothing auto-executes). Dispatch, watch the per-host output stream live, then confirm
the action in **Audit** — actor, host, full input, output, timing.

Everything you just used also exists as `partout ctl` (CLI), the REST API, and MCP
tools for AI assistants — same policy gates, same audit trail.

## 4. Look around (all pre-seeded on first run)

- **Policies / Alerts** — a preset of safety-net deny rules and standard alert rules
  (`default-*`, editable) is seeded on first boot. Review it; it is your safety net,
  not ours.
- **Observe — Services / Certificates / Configs** — the read side: systemd unit
  health, TLS certificate expiry, haproxy/nginx validity + drift. Custom units are the
  ones you label (`PARTOUT_SERVICE_LABELS` on the agent) or that live under
  `/etc/systemd/system`.
- **Updates** — CVE-ranked package updates per host, and fleet release rollouts
  (upload an agent release; a draft rollout is pre-armed for you to start).
- **Elevation** — the privilege documents provisioning ships (the seeded
  `default-baseline` + your own), with each connected host's effective scope
  matched by hash. **Jobs** — the seeded `default-daily-package-updates` is
  paused and ready: enable it and every host gets the 04:30 UTC update job.
- **Assistant** — chat with your fleet in natural language over the same governed
  tool surface: ask "any certs expiring soon on role:web?", request a playbook run
  (it parks on approvals like any write). Configure it in **Settings → Assistant**
  (admin): any OpenAI-compatible endpoint works — for a fully local setup,
  `ollama serve` + `ollama pull qwen3:32b`, then base URL
  `http://127.0.0.1:11434/v1` (keyless, zero egress). Profiles cap what the
  model may call; `decide_approval` is never assistant-reachable.

## 5. From demo to production

The embedded demo is a self-contained process with its own database — starting a real
server is a fresh start, not a migration. On a systemd Linux box the release's
**installer bundle** (`partout_install_<version>_linux_<arch>.tar.gz`: binary +
`install-server.sh` + units) is the one-command day-1 install — no toolchain, no
git checkout needed (see the README quick start). From a repo checkout:
**`sudo bash scripts/install-server.sh --binary ./partout --tls on`** (user, env with generated tokens, units, daily backup timer, doctor,
healthz — see [deployment.md](deployment.md) §3.1); back up the SQLite file
(`partout ctl db-backup`) — it is the control plane's state.
