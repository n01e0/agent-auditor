# Documentation index

This directory is the entrypoint for the repository documentation.

## Start here

- product requirements: [`PRD.md`](PRD.md)
- architecture overview: [`architecture/overview.md`](architecture/overview.md)
- separate-machine audit preview boundary: [`architecture/preview-readiness-boundary.md`](architecture/preview-readiness-boundary.md)
- separate-machine audit preview gap matrix: [`architecture/preview-readiness-gap-matrix.md`](architecture/preview-readiness-gap-matrix.md)
- architecture index: [`architecture/README.md`](architecture/README.md)
- runbook index: [`runbooks/README.md`](runbooks/README.md)
- policy contract: [`policies/rego-contract.md`](policies/rego-contract.md)
- schema contracts: [`schemas/`](schemas)

## Recommended reading order

If you are new to the repository:

1. [`PRD.md`](PRD.md)
2. [`architecture/overview.md`](architecture/overview.md)
3. [`architecture/preview-readiness-boundary.md`](architecture/preview-readiness-boundary.md)
4. [`architecture/preview-readiness-gap-matrix.md`](architecture/preview-readiness-gap-matrix.md)
5. [`architecture/coverage-matrix.md`](architecture/coverage-matrix.md)
6. the capability-specific runbook you care about under [`runbooks/`](runbooks/README.md)
7. the deeper architecture notes under [`architecture/`](architecture/README.md)

## Sections

### Architecture

Design notes, boundaries, catalogs, constraints, and phase-specific foundations:

- [`architecture/README.md`](architecture/README.md)

### Runbooks

Local developer runbooks for reproducing current PoCs and preview behavior:

- [`runbooks/README.md`](runbooks/README.md)

### Policies

Policy evaluation contracts and Rego-facing documentation:

- [`policies/rego-contract.md`](policies/rego-contract.md)

### Schemas

JSON schema contracts for events, sessions, approvals, and policy decisions:

- [`schemas/event-envelope.schema.json`](schemas/event-envelope.schema.json)
- [`schemas/session.schema.json`](schemas/session.schema.json)
- [`schemas/approval-request.schema.json`](schemas/approval-request.schema.json)
- [`schemas/policy-decision.schema.json`](schemas/policy-decision.schema.json)

