# hostd exec/exit PoC: local runbook

This runbook covers the current `agent-auditor-hostd` exec/exit PoC as it exists after P1-6.

## What this PoC currently proves

The current PoC is intentionally narrow:

- `agent-auditor-hostd` can load a minimal embedded `aya` eBPF object
- userspace can decode deterministic exec/exit fixture payloads
- exec/exit can be correlated with `ProcessLifecycleKey { pid, ppid }`
- the decoded records can be normalized into temporary `agenta-core::EventEnvelope` values
- those normalized exec records can feed a preview-only process `allow` / `deny` / `require_approval` policy path plus hold/deny outcome reflection
- all of the above can be exercised in unprivileged CI with stable smoke coverage

## Prerequisites

- Linux development environment
- Rust toolchain installed
- repository checked out locally

The current PoC does **not** require root for the documented path below because it does not attach the programs to live kernel hooks yet.

## Quick start

From the repository root:

```bash
cargo run -p agent-auditor-hostd
```

Expected output includes these categories of lines:

- `loader=...`
- `loader_runtime=...`
- `event_log_exec=...`
- `event_log_exit=...`
- `lifecycle_log=...`
- `normalized_exec=...`
- `normalized_exit=...`
- `normalized_process_allow=...`
- `process_policy_decision_allow=...`
- `process_enforcement_allow=...`
- `process_approval_request_allow=...`
- `normalized_process_hold=...`
- `process_policy_decision_hold=...`
- `process_enforcement_hold=...`
- `process_approval_request_hold=...`
- `normalized_process_deny=...`
- `process_policy_decision_deny=...`
- `process_enforcement_deny=...`
- `process_approval_request_deny=...`

Example shape:

```text
agent-auditor-hostd bootstrap
session_id=sess_bootstrap_hostd agent_id=openclaw-main
loader=artifact=agent-auditor-hostd-ebpf/agent-auditor-hostd-poc.bpf.o ...
loader_runtime=artifact=agent-auditor-hostd-poc.bpf.o bytes=... programs=hostd_sched_process_exec,hostd_sched_process_exit maps=0
event_path=transport=ring_buffer raw_events=exec,exit stages=receive->decode->correlate->normalize->publish
event_log_exec=event=process.exec transport=ring_buffer pid=4242 ...
event_log_exit=event=process.exit transport=ring_buffer pid=4242 ...
lifecycle_log=event=process.lifecycle transport=ring_buffer correlation=pid_ppid ...
normalized_exec={...}
normalized_exit={...}
normalized_process_allow={...}
process_policy_decision_allow={...}
process_enforcement_allow={...}
process_approval_request_allow={...}
normalized_process_hold={...}
process_policy_decision_hold={...}
process_enforcement_hold={...}
process_approval_request_hold={...}
normalized_process_deny={...}
process_policy_decision_deny={...}
process_enforcement_deny={...}
process_approval_request_deny={...}
```

## Validation commands

### Full local validation

```bash
cargo fmt --all --check
cargo check --workspace --all-targets
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
```

### Run only the hostd smoke test

```bash
cargo test -p agent-auditor-hostd --test poc_smoke
```

### Run only hostd unit tests

```bash
cargo test -p agent-auditor-hostd --lib
```

## Where the fixture-backed behavior lives

- embedded object + deterministic fixture bytes:
  - `cmd/agent-auditor-hostd-ebpf/src/lib.rs`
- userspace decode / correlate / normalize path:
  - `cmd/agent-auditor-hostd/src/poc/event_path.rs`
- binary bootstrap preview output:
  - `cmd/agent-auditor-hostd/src/main.rs`
- checked-in smoke expectations:
  - `cmd/agent-auditor-hostd/tests/fixtures/hostd-smoke-fixtures.json`
- integration smoke test:
  - `cmd/agent-auditor-hostd/tests/poc_smoke.rs`

## Known limitations

This is still a PoC. Important constraints:

1. **No live kernel event collection yet**
   - the embedded `aya` object is loaded and parsed, but not attached to real tracepoints in the documented path
   - exec/exit delivery is currently driven by deterministic fixture payloads

2. **No real ring buffer/perf buffer consumption yet**
   - the `ring_buffer` transport label describes the intended boundary
   - the current userspace path does not read from a live kernel-backed buffer

3. **Correlation is intentionally minimal**
   - exec/exit matching uses only `ProcessLifecycleKey { pid, ppid }`
   - this is good enough for the PoC shape, but it is not a robust long-term identity model

4. **Normalized records are temporary**
   - P1-5 emits provisional `agenta-core::EventEnvelope` values
   - field choices like event ids, actor labeling, host id, and attribute layout are still PoC-level and may change

5. **Process deny / hold remains preview-only**
   - the bootstrap now models `allow`, `deny`, and `require_approval` outcomes for normalized `process.exec` events
   - this is still a record-level preview and not a real pre-exec block or pause on a live host

6. **No live process enforcement yet**
   - there is no pre-exec interception, task suspension, approval resume, or safe interactive gate in this PoC
   - the preview path exists to define the boundary and record shape before hook selection lands

7. **Linux-local only**
   - this runbook describes the local Rust workflow for the current hostd PoC
   - container runtime integration, Kubernetes behavior, and production deployment are out of scope here

## Cross-cutting enforcement docs

For the shared filesystem/process enforcement preview seam layered on top of this exec path, also see:

- [`hostd-enforcement-foundation-local.md`](hostd-enforcement-foundation-local.md)
- [`../architecture/hostd-enforcement-known-constraints.md`](../architecture/hostd-enforcement-known-constraints.md)

## When this runbook should change

Update this document when any of the following happens:

- hostd starts attaching the eBPF programs for real
- userspace begins reading from an actual ring buffer or perf buffer
- the lifecycle correlation key changes
- normalized event fields stop being temporary
- local execution requires elevated privileges or additional setup
