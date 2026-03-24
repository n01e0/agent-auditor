# deploy/

This directory is reserved for deployment assets.

## Current state

Deployment packaging is still minimal. The repository currently ships architecture notes and local runbooks before a full deployment stack.

## What exists today

- documentation for deployment hardening minimums:
  - [`../docs/architecture/deployment-hardening-minimums.md`](../docs/architecture/deployment-hardening-minimums.md)
- local developer runbooks under:
  - [`../docs/runbooks/README.md`](../docs/runbooks/README.md)

## Planned contents

- local single-node development deployment
- Docker Compose example
- containerized control-plane / hostd development setup
- Kubernetes manifests or Helm later
- system prerequisites for eBPF + fanotify paths

Until those assets exist, treat this directory as a placeholder and use the runbooks + architecture docs as the source of truth.
