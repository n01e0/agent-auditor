# deploy/

This directory is reserved for deployment assets.

## Current state

Deployment packaging is still minimal. The repository currently ships architecture notes and local runbooks before a full deployment stack.

## What exists today

- documentation for deployment hardening minimums:
  - [`../docs/architecture/deployment-hardening-minimums.md`](../docs/architecture/deployment-hardening-minimums.md)
- container proxy topology boundary for OpenClaw / Hermes:
  - [`../docs/architecture/container-proxy-topologies.md`](../docs/architecture/container-proxy-topologies.md)
- real-runtime audit readiness boundary for the handoff from stand-in runtimes to real OpenClaw / Hermes verification:
  - [`../docs/architecture/real-runtime-audit-readiness-boundary.md`](../docs/architecture/real-runtime-audit-readiness-boundary.md)
- the current source-of-truth runbook for a separate-machine audit preview setup:
  - [`../docs/runbooks/separate-machine-audit-preview-local.md`](../docs/runbooks/separate-machine-audit-preview-local.md)
- local developer runbooks under:
  - [`../docs/runbooks/README.md`](../docs/runbooks/README.md)
- a systemd service artifact + sample environment config for source-tree-independent hostd startup:
  - [`systemd/agent-auditor-hostd.service`](systemd/agent-auditor-hostd.service)
  - [`systemd/agent-auditor-hostd.env.sample`](systemd/agent-auditor-hostd.env.sample)
- a container-first compose example for live proxy experimentation:
  - [`compose.yaml`](compose.yaml)
  - [`compose.env.sample`](compose.env.sample)
  - [`proxy/mitmproxy-live-proxy.py`](proxy/mitmproxy-live-proxy.py)

## Compose topologies

`compose.yaml` now ships two proxy topologies that write into the same hostd observed-runtime contract.
The boundary and non-goals are fixed in [`../docs/architecture/container-proxy-topologies.md`](../docs/architecture/container-proxy-topologies.md).

- **A / default**: explicit forward proxy per runtime
  - `openclaw-runtime -> openclaw-forward-proxy -> hostd`
  - `hermes-runtime -> hermes-forward-proxy -> hostd`
- **B / optional profile**: per-agent sidecar proxy
  - `openclaw-runtime-sidecar -> openclaw-proxy-sidecar -> hostd`
  - `hermes-runtime-sidecar -> hermes-proxy-sidecar -> hostd`

The default path is A. Enable B with `--profile sidecar`.

## Quick start

```bash
cp deploy/compose.env.sample deploy/compose.env

docker compose -f deploy/compose.yaml --env-file deploy/compose.env config

docker compose -f deploy/compose.yaml --env-file deploy/compose.env up hostd openclaw-forward-proxy hermes-forward-proxy openclaw-runtime hermes-runtime
```

To add the sidecar examples too:

```bash
docker compose -f deploy/compose.yaml --env-file deploy/compose.env --profile sidecar up
```

The runtime services in the compose file are smoke-friendly stand-ins built with `curlimages/curl`.
Replace their `image` / `command` with the real OpenClaw or Hermes container while keeping the same proxy env wiring.

That swap should be read through [`../docs/architecture/real-runtime-audit-readiness-boundary.md`](../docs/architecture/real-runtime-audit-readiness-boundary.md): the checked-in compose file currently proves stand-in topology smoke, while later P18 work is what makes the repository genuinely handoff-ready for human-run OpenClaw / Hermes verification.

## Planned contents

- Kubernetes manifests or Helm later
- system prerequisites for eBPF + fanotify paths
- stronger production certificate distribution / trust bootstrapping

For the current minimum separate-machine preview path, start with [`../docs/runbooks/separate-machine-audit-preview-local.md`](../docs/runbooks/separate-machine-audit-preview-local.md).
