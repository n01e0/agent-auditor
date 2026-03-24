# agent-auditor

Linux-first agent execution security / governance for autonomous agents.

`agent-auditor` is a Rust workspace for observing, classifying, auditing, and gradually governing what permissioned agents do on a Linux host and across provider APIs. The project currently covers runtime activity, provider semantic actions, approval/audit flows, and productization hardening in a proof-of-concept / pre-product form.

## Status

This repository is **active but not production-ready**.

What already exists:

- process exec/exit observation PoC
- filesystem governance PoC
- network destination governance PoC
- secret access modeling and approval/audit path
- enforcement preview paths for deny / hold / approval semantics
- Google Workspace semantic action modeling
- GitHub semantic action modeling
- generic REST / OAuth governance foundation
- messaging / collaboration governance foundation
- policy authoring / explainability foundation
- productization / hardening groundwork

What is still missing:

- production-grade inline interception
- polished control plane / UI
- stable deployment packaging
- long-term compatibility guarantees
- end-to-end integration with external runtimes at production confidence

## Repository layout

```text
agent-auditor/
  cmd/                binaries
  crates/             shared Rust crates
  docs/               architecture, schemas, runbooks, roadmaps
  examples/policies/  sample Rego policy fragments
  deploy/             deployment notes (still minimal)
```

## Binaries

Current workspace binaries:

- `agent-auditor-hostd` — host-side collector / enforcement preview daemon
- `agent-auditor-hostd-ebpf` — embedded eBPF object builder for the hostd PoC
- `agent-auditor-controld` — control-plane preview binary
- `agent-auditor-cli` — local diagnostics / admin preview binary

## Installation

Right now, installation is developer-oriented.

### Prerequisites

- Linux
- Rust toolchain (workspace currently targets edition 2024; see `Cargo.toml`)
- standard C/Rust build environment suitable for local Rust development

### Clone

```bash
git clone git@github.com:n01e0/agent-auditor
cd agent-auditor
```

### Build

```bash
cargo build
```

### Validate the workspace

```bash
cargo fmt --all --check
cargo check --workspace --all-targets
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
```

## Quick start

The easiest current entrypoint is the host daemon preview:

```bash
cargo run -p agent-auditor-hostd
```

This does **not** yet mean "start a production daemon on a live host". In the current repository state it runs the checked-in preview/bootstrap path described in the runbooks.

Other preview entrypoints:

```bash
cargo run -p agent-auditor-controld
cargo run -p agent-auditor-cli
```

## Usage guide

Because the project is still phase-driven, the most useful way to use it today is:

1. read the architecture overview
2. choose the capability area you want to inspect
3. use the matching runbook to reproduce the current PoC locally
4. run the focused tests for that area

Recommended order:

1. [`docs/README.md`](docs/README.md)
2. [`docs/architecture/overview.md`](docs/architecture/overview.md)
3. relevant runbook under [`docs/runbooks/`](docs/runbooks/README.md)
4. related architecture notes under [`docs/architecture/`](docs/architecture/README.md)

## Configuration

There is **not yet** a single stable end-user configuration file.

Current configuration surfaces are split across:

- policy examples in [`examples/policies/`](examples/policies)
- schema contracts in [`docs/schemas/`](docs/schemas)
- policy/evaluation contracts in [`docs/policies/`](docs/policies)
- architecture docs describing current mode semantics and constraints

In practice, today you should think of configuration as three layers:

### 1. Policy layer

Sample Rego fragments live in:

- `examples/policies/sensitive_fs.rego`
- `examples/policies/process_exec.rego`
- `examples/policies/network_destination.rego`
- `examples/policies/secret_access.rego`
- `examples/policies/gws_action.rego`
- `examples/policies/github_action.rego`
- `examples/policies/generic_rest_action.rego`
- `examples/policies/messaging_action.rego`

### 2. Event / decision schema layer

Contracts live in:

- `docs/schemas/event-envelope.schema.json`
- `docs/schemas/session.schema.json`
- `docs/schemas/approval-request.schema.json`
- `docs/schemas/policy-decision.schema.json`

### 3. Behavior / mode semantics layer

Current mode, coverage, and known-constraint documentation lives under:

- `docs/architecture/`
- `docs/runbooks/`

## Documentation map

Start here:

- docs index: [`docs/README.md`](docs/README.md)

Key entrypoints:

- product requirements: [`docs/PRD.md`](docs/PRD.md)
- architecture overview: [`docs/architecture/overview.md`](docs/architecture/overview.md)
- architecture index: [`docs/architecture/README.md`](docs/architecture/README.md)
- runbook index: [`docs/runbooks/README.md`](docs/runbooks/README.md)
- policy contract: [`docs/policies/rego-contract.md`](docs/policies/rego-contract.md)

## Development workflow

Typical local workflow:

```bash
cargo fmt --all --check
cargo check --workspace --all-targets
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
```

If you are working on a specific slice, prefer the focused runbook and focused tests for that area rather than reading the entire repository from scratch.

## Current capability areas

The repository currently contains architecture and runbook material for:

- runtime / host observation
- filesystem governance
- network destination governance
- secret access governance
- enforcement preview paths
- Google Workspace semantic governance
- GitHub semantic governance
- generic REST / OAuth governance
- messaging / collaboration governance
- policy authoring / explainability
- productization / hardening gaps

## Limitations

A few important caveats:

- many paths are preview or PoC quality rather than production-grade enforcement
- some flows model future runtime behavior before live hooks exist
- documentation is currently phase-oriented because the implementation has grown iteratively
- deployment guidance is still minimal compared with the architecture and testing material

## Near-term direction

The current direction is to close productization gaps and make the repository easier to operate and reason about before pushing further into deeper runtime integrations.
