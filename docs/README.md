# Partout documentation

Start at the [README](../README.md) for the 60-second quickstart.

## User docs

| Doc | What it covers |
|---|---|
| [getting-started.md](getting-started.md) | Guided 5-minute walkthrough: first host, first command, the audit check. *Last verified against v0.9.19.* |
| [architecture.md](architecture.md) | Modes, AgentStream protocol, policy → approval → signed-decision chain, storage, security model, testing |
| [deployment.md](deployment.md) | Install paths (release bundle, systemd, Docker/compose, cloud-init, Helm), TLS/reverse-proxy patterns, full config reference |
| [operations.md](operations.md) | Day-2 ops: backups, audit-chain key management, upgrades, runbooks, troubleshooting, compliance |
| [roadmap.md](roadmap.md) | Milestone plan & status (single source of truth) + shipped feature deep-dives |
| [assistant.md](assistant.md) | The built-in LLM assistant and the MCP server for external AI assistants |
| [spec-file-root.md](spec-file-root.md) | File-surface confinement (the agent file root) |
| [ui-guidelines.md](ui-guidelines.md) | Web UI definition: IA, design tokens, components |

Also: [PRD.md](../PRD.md) (product spec, decisions log, non-goals),
[CONTRIBUTING.md](../CONTRIBUTING.md), [SECURITY.md](../SECURITY.md),
[LICENSE](../LICENSE), [screenshots/](screenshots/),
[partout-architecture.svg](../partout-architecture.svg).

## Project internals (`dev/`)

Research, evaluation instruments, and design proposals — not user docs:

- [dev/ux-improvements.md](dev/ux-improvements.md) — living UX evaluation (heuristic findings, shipped fixes)
- [dev/walkthrough.md](dev/walkthrough.md) — moderated-operator walkthrough instrument (run before each beta tag)
- [dev/proposal-setup-elevation-ux.md](dev/proposal-setup-elevation-ux.md) — setup/elevation UX design record
