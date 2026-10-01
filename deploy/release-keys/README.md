# Release signing keys (M8.1 fleet self-update)

This directory holds the Ed25519 **release signing** keypair for the signed
update repository that `partout update` consumes.

| File | Committed? | Where it goes |
|---|---|---|
| `release-key.pub` | **yes** — it is the trust anchor, meant to be distributed | every agent's `PARTOUT_RELEASE_KEY` (`/etc/partout/agent.env`), the server's `PARTOUT_RELEASE_VERIFY_KEY`, provisioned release keys on enrolled hosts |
| `release-key.priv` | **no** (gitignored, mode 0600) | operator's build machine only. Never on a fleet host, never in a log, never in chat |

The private key can sign release binaries; a fleet that trusts the public key
will download and **execute** anything signed with it. Treating it as
compromised = full fleet compromise. If it is ever exposed: rotate
(`partout ctl update keygen`), push the new **public** key to the fleet,
re-sign — agents fail closed on signatures from the old key.

## Signing a release

```bash
PARTOUT_RELEASE_KEY_PRIV="$(cat deploy/release-keys/release-key.priv)" \
  bash scripts/release-publish.sh v0.9.5
```

Builds `dist/release-repo/<version>/partout-<version>-<arch>-{server,agent}`
(+ `.sig`), independently re-verifies every artifact against the public key,
and only then writes `dist/release-repo/latest`. Publishing (rsync/S3 to the
fleet's `PARTOUT_RELEASE_REPO`) is a deliberate operator step after that —
the script never uploads.
