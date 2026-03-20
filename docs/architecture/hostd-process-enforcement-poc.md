# hostd process deny / hold PoC boundary

This note defines the first boundary for process-side deny / approval-hold planning in `agent-auditor-hostd`.

## Goal of P5-5

Keep the process enforcement preview honest before any live pre-exec hook, ptrace/LSM decision, or control-plane approval workflow is treated as real enforcement.

The immediate rule is:

- **event path** owns decoding and normalizing `process.exec` observations into `agenta-core::EventEnvelope`
- **policy** owns returning the exact `allow` / `deny` / `require_approval` result for that normalized exec candidate
- **enforcement decision / hold / deny** owns routing the process decision into an explicit preview outcome using the shared enforcement foundation seam
- **audit / approval reflection** owns copying that realized preview outcome back into the event / approval record shape
- the shared seam is a normalized `process.exec` event plus the exact policy output and optional approval request

This is intentionally still a **preview path**, not a claim that the host can stop an exec before completion.

## Code layout

- exec / exit observation:
  - `cmd/agent-auditor-hostd/src/poc/event_path.rs`
- generic enforcement foundation:
  - `cmd/agent-auditor-hostd/src/poc/enforcement/`
- checked-in process policy example:
  - `examples/policies/process_exec.rego`
- bootstrap preview wiring:
  - `cmd/agent-auditor-hostd/src/main.rs`

## Responsibility split

### Event path

Owns:

- decoding exec fixture payloads
- producing normalized `process.exec` envelopes
- preserving process attributes like pid / ppid / command / filename

Does **not** own:

- deciding whether the process should be denied or held
- approval request generation
- enforcement outcome reflection

### Policy

Owns:

- expressing the exact process rule in Rego
- returning `allow`, `deny`, or `require_approval`
- defining the policy reason / severity / approval constraint

Current checked-in preview policy is intentionally narrow:

- `cargo`-like default execs fall through to `allow`
- `ssh` requires approval
- `rm` is denied

### Enforcement preview

Owns:

- mapping the process policy decision onto `allow` / `hold` / `deny`
- carrying the exact decision through the shared enforcement seam
- producing preview `enforcement` metadata for events and approval records

Does **not** own:

- live pre-exec interception
- process suspension/resume mechanics
- a real reviewer workflow

## Why this split now

This keeps later process tasks separate:

- live pre-exec experiments can change independently from Rego policy shape
- approval workflow work can evolve without redefining the normalized process event
- fail-open / fail-closed claims stay constrained to documented runtime reality

## Explicitly out of scope for P5-5

- real process blocking before exec completion
- pausing a task until reviewer approval arrives
- process tree inheritance or child-policy propagation
- signal / LSM / ptrace hook selection
- production-safe deadlock handling for interactive commands

## Related docs

- exec/exit PoC boundary: [`hostd-exec-exit-poc.md`](hostd-exec-exit-poc.md)
- enforcement foundation: [`hostd-enforcement-foundation.md`](hostd-enforcement-foundation.md)
- enforcement local runbook: [`../runbooks/hostd-enforcement-foundation-local.md`](../runbooks/hostd-enforcement-foundation-local.md)
- enforcement known constraints: [`hostd-enforcement-known-constraints.md`](hostd-enforcement-known-constraints.md)
- failure behavior policy: [`failure-behavior.md`](failure-behavior.md)
- local runbook: [`../runbooks/hostd-exec-exit-poc-local.md`](../runbooks/hostd-exec-exit-poc-local.md)
