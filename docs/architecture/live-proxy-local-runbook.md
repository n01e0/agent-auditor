# live proxy local runbook

This runbook describes the smallest useful local workflow for the checked-in live proxy seam.

## Goal

Give future contributors one place to answer:

- what to run locally
- which modules own which stage
- how to exercise the seam end to end
- where to extend fixtures or preview adapters safely

The runbook is intentionally scoped to the current repository PoC. It does **not** describe real proxy deployment, certificates, browser installation, or host/network plumbing.

## Current checked-in seam

The live proxy seam currently spans these checked-in areas:

1. **proxy contract / seam ownership**
   - `cmd/agent-auditor-hostd/src/poc/live_proxy/contract.rs`
   - `proxy_seam.rs`
   - `session_correlation.rs`
2. **shared live semantic input**
   - `crates/agenta-core/src/live.rs`
   - `semantic_conversion.rs`
3. **preview adapters**
   - `generic_rest.rs`
   - `gws.rs`
   - `github.rs`
   - `messaging.rs`
4. **mode / policy / approval / audit reflection**
   - `mode.rs`
   - `policy.rs`
   - `approval.rs`
   - `audit.rs`
5. **fixture and smoke coverage**
   - `fixtures.rs`
   - `cmd/agent-auditor-hostd/tests/live_proxy_seam_smoke.rs`

## Fast local checklist

From the repository root:

```bash
cargo fmt --check
cargo check
cargo test
cargo clippy -- -D warnings
```

That is the baseline pre-push gate for this slice.

## Targeted live proxy commands

### 1. Run the seam fixture unit tests

```bash
cargo test -p agent-auditor-hostd live_proxy::fixtures::tests -- --nocapture
```

Use this when editing:

- fixture coverage
- mode/status expectations
- annotated live preview events

### 2. Run the live proxy smoke test

```bash
cargo test -p agent-auditor-hostd --test live_proxy_seam_smoke -- --nocapture
```

Use this when changing:

- policy projection
- approval materialization
- audit reflection
- end-to-end expectations across modes or consumers

### 3. Run only live proxy module tests

```bash
cargo test -p agent-auditor-hostd live_proxy:: -- --nocapture
```

Use this for broader live proxy refactors without running every crate test first.

### 4. Re-run a specific downstream slice

Examples:

```bash
cargo test -p agent-auditor-hostd live_proxy::generic_rest::tests -- --nocapture
cargo test -p agent-auditor-hostd live_proxy::gws::tests -- --nocapture
cargo test -p agent-auditor-hostd live_proxy::github::tests -- --nocapture
cargo test -p agent-auditor-hostd live_proxy::messaging::tests -- --nocapture
cargo test -p agent-auditor-hostd live_proxy::mode::tests -- --nocapture
cargo test -p agent-auditor-hostd live_proxy::audit::tests -- --nocapture
```

## Recommended edit workflow

### If you change the request contract or seam ownership

Run at least:

```bash
cargo test -p agent-auditor-hostd live_proxy::contract::tests -- --nocapture
cargo test -p agent-auditor-hostd live_proxy::tests -- --nocapture
cargo test -p agent-auditor-hostd --test live_proxy_seam_smoke -- --nocapture
```

### If you change mode semantics or reflected status fields

Run at least:

```bash
cargo test -p agent-auditor-hostd live_proxy::mode::tests -- --nocapture
cargo test -p agent-auditor-hostd live_proxy::policy::tests -- --nocapture
cargo test -p agent-auditor-hostd live_proxy::approval::tests -- --nocapture
cargo test -p agent-auditor-hostd live_proxy::audit::tests -- --nocapture
cargo test -p agent-auditor-hostd --test live_proxy_seam_smoke -- --nocapture
```

### If you add or edit a provider preview adapter

Run the adapter-specific tests plus the smoke test:

```bash
cargo test -p agent-auditor-hostd live_proxy::gws::tests -- --nocapture
cargo test -p agent-auditor-hostd live_proxy::github::tests -- --nocapture
cargo test -p agent-auditor-hostd live_proxy::messaging::tests -- --nocapture
cargo test -p agent-auditor-hostd --test live_proxy_seam_smoke -- --nocapture
```

## How to extend the fixture catalog

The repository-owned seam fixture catalog lives in:

- `cmd/agent-auditor-hostd/src/poc/live_proxy/fixtures.rs`

When adding a new fixture:

1. choose the downstream consumer (`generic_rest`, `gws`, `github`, `messaging`)
2. choose the live mode (`shadow`, `enforce_preview`, `unsupported`)
3. build an annotated event using the checked-in preview adapter and `policy.annotate_preview_event(...)`
4. set explicit expectations for:
   - policy decision
   - coverage posture
   - mode behavior
   - mode status
   - record status
   - coverage gap
   - approval materialization
   - wait state
5. run the smoke test

If a change breaks the smoke test, treat that as a real contract drift until proven otherwise.

## How to debug failures

### Fixture unit test failure

Usually means one of these drifted:

- mode annotation on the event
- expected consumer label
- live request summary annotation
- expected mode/status strings

Start in:

- `fixtures.rs`
- `mode.rs`
- `policy.rs`

### Smoke test failure

Usually means one of these stages changed behavior:

- policy evaluation result
- approval materialization rules
- audit reflection fields
- mode-specific coverage gap or record status

Work in this order:

1. `mode.rs`
2. `policy.rs`
3. `approval.rs`
4. `audit.rs`

### Provider adapter failure

Usually means route-hint or target-hint assumptions changed.

Check:

- `generic_rest.rs`
- `gws.rs`
- `github.rs`
- `messaging.rs`

Then compare against the matching architecture notes.

## Store-related test hygiene

The live preview audit tests use per-test local store directories under `target/`.

If you add new persistence-heavy tests, keep them isolated the same way. Do **not** reuse one shared PoC store directory across multiple tests, or CI can fail nondeterministically from leftover records.

## What this runbook does not cover

This runbook does **not** cover:

- real HTTP interception setup
- certificate trust bootstrapping
- browser relay install/config
- sidecar deployment
- production operator workflows
- approval queue reconciliation
- inline pause/resume/deny behavior

Those remain outside the current repository PoC.

## Related docs

- phase boundary: [`live-proxy-interception-foundation.md`](live-proxy-interception-foundation.md)
- request contract: [`live-proxy-http-request-contract.md`](live-proxy-http-request-contract.md)
- shared live envelope: [`generic-live-action-envelope.md`](generic-live-action-envelope.md)
- provider adapter boundaries: [`provider-live-preview-adapter-boundaries.md`](provider-live-preview-adapter-boundaries.md)
- mode semantics: [`live-preview-mode-semantics.md`](live-preview-mode-semantics.md)
- record reflection: [`live-preview-record-reflection.md`](live-preview-record-reflection.md)
- test fixtures: [`live-proxy-test-fixtures.md`](live-proxy-test-fixtures.md)
- known constraints: [`live-proxy-known-constraints.md`](live-proxy-known-constraints.md)
