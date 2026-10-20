# Partout server in Docker

Minimal, honest container for the **server**. The agent is a bare binary +
systemd unit on each managed host (docs/deployment.md §3.2) — do not containerize
it next to the server.

There is no published image yet; building locally is the path.

## Build & run

```sh
docker build -f deploy/docker/Dockerfile -t partout:local .
docker compose -f deploy/docker/docker-compose.yml up -d
```

Compose passes through:

| Env | Purpose |
|---|---|
| `PARTOUT_ADMIN_PASSWORD` | initial admin password (required) |
| `PARTOUT_TLS` | `on` — see below |
| `PARTOUT_DB_PATH` | points inside the volume (default set by the image) |

Healthcheck hits `GET /healthz` on the container's own TLS listener.

## TLS

`PARTOUT_TLS=on` bootstraps the CA on first start inside the volume. Agents
must trust that CA: fetch it from the server and point agents at it —
`partout ctl ca` (see docs/deployment.md §4 / §5). Hosts you manage over the
internet need to reach this container's published 8443.

## State, volumes, backup

The volume **is** the server. `/var/lib/partout` holds:

- `partout.db` (SQLite — all state)
- `tls/` (the bootstrapped CA material)
- `secret.key` (token-signing secret — losing it invalidates all sessions)

Back it up with `partout ctl db-backup` (docs/operations.md) or by stopping
the container and copying the volume; losing `secret.key` logs everyone out.

## Updates — the honest limitation

There is **no systemd inside the container**, and partout's one-command
`partout update` / `scripts/update-server.sh` supervised swap drives
`systemctl stop/start` on the *host's* `partout-server.service`. In a container
that mechanism does not apply: the in-container process is the target, so
`partout update`'s systemd-driven swap (and its crashloop rollback) is not
supported here.

Update the container by rebuilding the image and recreating the service:

```sh
docker build -f deploy/docker/Dockerfile -t partout:local .
docker compose -f deploy/docker/docker-compose.yml up -d
```

The state survives in the volume.
