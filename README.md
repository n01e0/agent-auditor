# agent-auditor

Agent execution security / governance for Linux-hosted autonomous agents.

## Current status

This repository currently contains an initial product requirements draft.

- PRD: [`docs/PRD.md`](docs/PRD.md)

## Product direction

- Linux-first
- Container-first (Docker / Kubernetes / Podman)
- Runtime monitoring via eBPF + fanotify
- Browser / Google Workspace governance after filesystem and process coverage
- Policy engine based on OPA / Rego
- microVM support deferred until after the initial container-focused release
