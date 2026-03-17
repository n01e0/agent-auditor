# agent-auditor

Agent execution security / governance for Linux-hosted autonomous agents.

## Current status

This repository currently contains the initial product framing and core design contracts.

- PRD: [`docs/PRD.md`](docs/PRD.md)
- Architecture overview: [`docs/architecture/overview.md`](docs/architecture/overview.md)
- Coverage matrix: [`docs/architecture/coverage-matrix.md`](docs/architecture/coverage-matrix.md)
- Rust implementation direction: [`docs/architecture/rust-implementation.md`](docs/architecture/rust-implementation.md)
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
