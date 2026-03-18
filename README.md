# agent-auditor

Agent execution security / governance for Linux-hosted autonomous agents.

## Current status

This repository currently contains the initial product framing and core design contracts.

- PRD: [`docs/PRD.md`](docs/PRD.md)
- Architecture overview: [`docs/architecture/overview.md`](docs/architecture/overview.md)
- Coverage matrix: [`docs/architecture/coverage-matrix.md`](docs/architecture/coverage-matrix.md)
- Rust implementation direction: [`docs/architecture/rust-implementation.md`](docs/architecture/rust-implementation.md)
- hostd exec/exit PoC boundary: [`docs/architecture/hostd-exec-exit-poc.md`](docs/architecture/hostd-exec-exit-poc.md)
- hostd filesystem PoC boundary: [`docs/architecture/hostd-filesystem-poc.md`](docs/architecture/hostd-filesystem-poc.md)
- hostd network PoC boundary: [`docs/architecture/hostd-network-poc.md`](docs/architecture/hostd-network-poc.md)
- hostd network domain attribution: [`docs/architecture/hostd-network-domain-attribution.md`](docs/architecture/hostd-network-domain-attribution.md)
- hostd filesystem PoC known constraints: [`docs/architecture/hostd-filesystem-known-constraints.md`](docs/architecture/hostd-filesystem-known-constraints.md)
- hostd exec/exit PoC local runbook: [`docs/runbooks/hostd-exec-exit-poc-local.md`](docs/runbooks/hostd-exec-exit-poc-local.md)
- hostd filesystem PoC local runbook: [`docs/runbooks/hostd-filesystem-poc-local.md`](docs/runbooks/hostd-filesystem-poc-local.md)
- Event schema: [`docs/schemas/event-envelope.schema.json`](docs/schemas/event-envelope.schema.json)
- Session schema: [`docs/schemas/session.schema.json`](docs/schemas/session.schema.json)
- Approval request schema: [`docs/schemas/approval-request.schema.json`](docs/schemas/approval-request.schema.json)
- Policy decision schema: [`docs/schemas/policy-decision.schema.json`](docs/schemas/policy-decision.schema.json)
- Rego contract: [`docs/policies/rego-contract.md`](docs/policies/rego-contract.md)
- Example policy: [`examples/policies/sensitive_fs.rego`](examples/policies/sensitive_fs.rego)

## Product direction

- Linux-first
- Container-first (Docker / Kubernetes / Podman)
- Runtime monitoring via eBPF + fanotify
- Browser / Google Workspace governance after filesystem and process coverage
- Policy engine based on OPA / Rego
- microVM support deferred until after the initial container-focused release

## Workspace bootstrap

The repository now includes an initial Rust workspace:

- `crates/agenta-core` — shared domain models for sessions, events, approvals, and policy decisions
- `crates/agenta-policy` — policy input models and evaluation boundary
- `cmd/agent-auditor-hostd` — host-side collector / enforcement daemon bootstrap
- `cmd/agent-auditor-controld` — control-plane bootstrap
- `cmd/agent-auditor-cli` — operator CLI bootstrap

Current goal: keep the type system and process boundaries stable before deeper `aya` / fanotify implementation starts.
