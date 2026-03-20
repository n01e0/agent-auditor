# hostd enforcement foundation boundary

This note fixes the first internal split for the `agent-auditor-hostd` enforcement phase.

## Goal of P5-1

Keep the first deny / approval-hold work honest about ownership before filesystem blocking, process-gating experiments, and durable enforcement audit wiring land.

The immediate rule is:

- **decision** owns consuming the normalized action candidate, the exact policy output, and coverage context, then routing that into an explicit enforcement directive
- **hold** owns approval-required waiting state, release / expiry boundaries, and preserving hold context for later audit
- **deny** owns the technical block attempt plus explicit fallback reporting when coverage is not strong enough to block
- **audit** owns appending the exact policy decision plus realized enforcement outcome to logs / stores without re-running policy or runtime mechanics
- the shared seams are a small decision → {hold, deny} contract and a small {hold, deny} → audit contract that both keep policy-output fidelity intact

This split is intentionally generic across the first two scopes that need real enforcement planning now:

- `filesystem`
- `process`

Network and secret-access already produce policy / audit-shaped records, but they are not yet in scope for node-local deny / hold mechanics in this phase.

## Code layout

`cmd/agent-auditor-hostd/src/poc/enforcement/`

- `contract.rs`
  - shared enforcement scopes, directives, statuses, and boundary field lists
  - policy-decision → enforcement-directive mapping contract
- `decision.rs`
  - policy-output routing plan after normalization / policy evaluation
  - future home for per-scope enforcement capability checks and fail-open / fail-closed routing
- `hold.rs`
  - approval-hold plan after decision routing
  - future home for short-lived action pause, approval wait handles, and release / expiry outcomes
- `deny.rs`
  - deny execution plan after decision routing
  - future home for the actual filesystem/process block attempt and explicit fallback reporting
- `audit.rs`
  - enforcement audit plan after hold / deny execution
  - future home for append-only enforcement outcome records and publish fanout
- `mod.rs`
  - assembles the enforcement foundation plan and tests the split

## Responsibility split

### Decision

Owns:

- accepting `normalized_event`, `policy_decision`, optional `approval_request`, and coverage context
- translating `allow` / `require_approval` / `deny` into explicit enforcement directives
- surfacing whether the current scope is expected to block, hold, or fall back to observe-only reporting
- handing off directive context to runtime stages without mutating audit state

Does **not** own:

- Rego / `agenta-policy` evaluation
- approval waiting state
- technical block attempts
- durable audit persistence

### Hold

Owns:

- the approval-required wait between decision routing and action completion
- hold handles, timeout / expiry state, and resume outcomes
- carrying forward the exact policy decision plus approval-request context
- handing off hold outcomes to audit

Does **not** own:

- policy recomputation
- technical deny mechanics
- final durable audit persistence

### Deny

Owns:

- the runtime block attempt for deny directives
- explicit status reporting for hard deny versus observe-only fallback
- preserving runtime failure reasons and coverage-gap context for audit
- handing off deny outcomes to audit

Does **not** own:

- approval waiting state
- policy recomputation
- durable audit persistence

### Audit

Owns:

- appending the exact policy decision and realized enforcement status together
- recording whether an action was held, denied, allowed through, or downgraded because the host lacked blocking coverage
- publishing enforcement records to logs and later control-plane sinks
- keeping decision-time and runtime-time status aligned in one record path

Does **not** own:

- policy evaluation
- hold queue lifecycle
- technical block mechanics

## Why this split now

This keeps the next tasks cleaner:

- **P5-2** can implement filesystem deny / approval-hold mechanics without deciding how audit or approval records are shaped
- **P5-3** can reflect enforcement results into shared event / approval / audit records without coupling itself to kernel-facing block logic
- **P5-5** can add the first process deny / hold boundary against the same decision-stage seam
- **P5-6 / P5-7** can test and document explicit hold / deny / fallback behavior instead of relying on implicit side effects

## Explicitly out of scope for P5-1

- concrete filesystem block or approval-hold implementation
- process enforcement hooks or signal choices
- final fail-open / fail-closed policy
- durable enforcement audit schema changes
- operator UI / API for approving or rejecting held actions
- browser / GWS enforcement

## Related docs

- architecture overview: [`overview.md`](overview.md)
- Rust implementation direction: [`rust-implementation.md`](rust-implementation.md)
- filesystem PoC boundary: [`hostd-filesystem-poc.md`](hostd-filesystem-poc.md)
- filesystem known constraints: [`hostd-filesystem-known-constraints.md`](hostd-filesystem-known-constraints.md)
- product requirements: [`../PRD.md`](../PRD.md)
- coverage matrix: [`coverage-matrix.md`](coverage-matrix.md)
