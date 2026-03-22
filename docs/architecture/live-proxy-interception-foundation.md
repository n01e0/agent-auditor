# live proxy / interception phase boundary

This note fixes the first internal split for the repository-wide live proxy / interception phase.

## Goal of P13-1

Keep the upcoming live interception work honest around the newly checked-in `agenta-core` generic live action envelope and before generic REST / GWS / GitHub / messaging live preview adapters start claiming real pause / deny coverage.

The immediate rule is:

- **proxy seam** owns accepting redaction-safe live HTTP request metadata from a forward proxy, browser relay, or sidecar proxy and stripping it down to a stable request handoff
- **session correlation** owns binding that live request handoff to the same `session_id` model already used by runtime hostd events, approval requests, and audit records
- **semantic conversion** owns turning a correlated live request into one generic live action seam plus the minimum provider / surface / target hints that downstream generic REST / GWS / GitHub / messaging adapters can consume before provider-local taxonomy runs
- **policy** owns bridging that generic live seam into existing policy surfaces and projecting `allow` / `deny` / `require_approval` plus live coverage posture / mode status
- **approval** owns live approval-hold feasibility, request wait-state materialization, and release / cancel linkage for actions that policy marks `require_approval`
- **audit** owns append-only reflection of the realized live mode, coverage gap, policy result, and approval linkage without replaying upstream capture, correlation, or taxonomy work
- the shared seams are a small proxy → correlation contract, a small correlation → semantic conversion contract, and a small semantic conversion → policy / approval / audit flow that all preserve the same redaction rule

Unlike the earlier preview-only semantic-governance slices, this phase is explicitly about **live request ownership**. It must answer three questions separately:

1. **What request did the proxy actually see?**
2. **Which agent session owns that request?**
3. **Which downstream semantic policy surface should evaluate it?**

If those three questions collapse into one blob, the repository will overfit to one adapter, leak raw payloads into policy, and blur the line between shadow-mode previews and validated hold / deny capability.

The redaction rule for this phase is explicit from the start: live proxy seams should carry method, authority, path, header classes, body classes, auth hints, request / correlation ids, session lineage, provider / surface hints, target hints, mode labels, and approval / audit linkage only. Raw header values, cookies, bearer tokens, request bodies, response bodies, message text, file bytes, rendered HTML, and provider-specific opaque payloads do not cross the boundary. The concrete minimal request contract fixed by P13-2 is documented in [`live-proxy-http-request-contract.md`](live-proxy-http-request-contract.md), and the shared `agenta-core` live envelope fixed by P13-3 is documented in [`generic-live-action-envelope.md`](generic-live-action-envelope.md).

## Code layout

`cmd/agent-auditor-hostd/src/poc/live_proxy/`

- `contract.rs`
  - checked-in shared seams, the repository-owned redaction rule, and the minimal live HTTP request contract for live proxy interception
- `proxy_seam.rs`
  - checked-in home for proxy ingress ownership and the redaction-safe live request handoff plan
- `session_correlation.rs`
  - checked-in home for request-to-session binding responsibilities before semantic conversion
- `semantic_conversion.rs`
  - checked-in home for the correlated-live-request → generic live seam boundary plan used by generic REST / GWS / GitHub / messaging adapters
- `generic_rest.rs`
  - checked-in home for the first live proxy → generic REST preview adapter on top of the shared live envelope
- `gws.rs`
  - checked-in home for the live proxy → GWS semantic-action preview adapter on top of the shared live envelope
- `github.rs`
  - checked-in home for the live proxy → GitHub semantic-action preview adapter on top of the shared live envelope
- `messaging.rs`
  - checked-in home for the live proxy → Slack / Discord messaging semantic-action preview adapter on top of the shared live envelope
- `policy.rs`
  - checked-in home for live semantic envelope → `agenta-policy` ownership and live coverage / mode projection responsibilities
- `approval.rs`
  - checked-in home for approval-hold feasibility and live wait-state boundary responsibilities after policy says `require_approval`
- `audit.rs`
  - checked-in home for append-only live preview / enforce-preview / unsupported record reflection
- `mod.rs`
  - bootstrap assembly and tests for the live proxy / interception split

The inline runtime work still remains outside this P13-1 boundary even after the checked-in live mode semantics landed:

- production-grade pause / resume / deny mechanics still sit beyond the current preview-only mode projection and record reflection path

## Responsibility split

### Proxy seam

Owns:

- accepting redaction-safe request metadata from forward proxies, browser relays, and sidecar proxies
- stripping raw headers / cookies / tokens / bodies down to stable classes before downstream handoff
- preserving stable request identity, correlation ids, transport hints, and mode hints
- surfacing one repository-owned live request seam that later correlation and semantic stages can reuse

Does **not** own:

- deciding session ownership
- deciding provider-neutral or provider-specific semantic action families
- evaluating policy
- materializing approval wait-state
- durable audit persistence

### Session correlation

Owns:

- binding live proxy requests to the same `session_id` model used by runtime hostd events and approval records
- deciding whether request ids, correlation ids, workspace hints, or runtime lineage are strong enough to claim session ownership
- preserving provider / surface hints for later semantic conversion without deciding the final semantic taxonomy
- surfacing uncorrelated or degraded ownership explicitly instead of forcing later layers to guess

Does **not** own:

- proxy capture or raw request parsing
- final generic or provider-specific semantic taxonomy
- policy outcome selection
- approval wait-state materialization
- durable audit persistence

### Semantic conversion

Owns:

- converting a correlated live proxy request into one generic live action seam before generic REST / GWS / GitHub / messaging adapters consume it
- deriving redaction-safe live surface, provider, and target hints without reopening raw payload access or pre-committing to provider-local action labels
- separating shared live-request facts from provider-specific taxonomy so multiple downstream adapters can reuse one upstream envelope
- surfacing unsupported or degraded semantic conversion as explicit status instead of silently skipping downstream policy

Does **not** own:

- raw proxy capture or request-body inspection
- deciding runtime session ownership
- final policy decisions
- approval wait-state materialization
- append-only audit persistence

### Policy

Owns:

- bridging generic live semantic envelopes into `agenta-policy`
- evaluating live requests against existing generic REST, GWS, GitHub, and messaging policy surfaces using only redaction-safe semantic fields
- projecting `allow` / `deny` / `require_approval` together with live coverage posture and mode status
- handing policy outputs to approval and audit stages without owning request pause / resume mechanics or durable record storage

Does **not** own:

- proxy capture
- session correlation
- semantic taxonomy or live envelope definition itself
- approval hold feasibility mechanics
- durable audit persistence

### Approval

Owns:

- deciding whether a live `require_approval` result can be represented as a real hold, an enforce-preview hold, or an unsupported fallback for the intercepted request class
- materializing approval-request state and release / cancel linkage without re-running policy evaluation or semantic conversion
- keeping pause / resume feasibility separate from durable audit persistence and reviewer UX
- surfacing the exact live wait-state boundary that later control-plane work will summarize

Does **not** own:

- proxy capture
- session correlation
- semantic conversion
- policy evaluation
- append-only audit storage or reconciliation

### Audit

Owns:

- appending live preview / enforce-preview / unsupported audit records without replaying proxy capture, session correlation, semantic conversion, or policy evaluation
- recording the exact realized interception status, coverage gap, and approval linkage so operators can tell modeled intent from real runtime effect
- preserving correlation ids and redaction-safe live request summaries for later control-plane reconciliation
- staying append-only rather than owning approval queue state, policy logic, or provider taxonomy

Does **not** own:

- proxy capture or request parsing
- session correlation
- semantic conversion
- policy evaluation or approval feasibility logic
- storage of raw headers, cookies, tokens, message bodies, or file bytes

## Boundary inputs and outputs fixed by P13-1

P13-1 fixed the ownership boundaries and P13-2 fixed the first concrete Rust request contract at the proxy seam.

### Upstream inputs into the live proxy seam

The proxy seam now relies on the concrete redaction-safe request facts fixed by [`live-proxy-http-request-contract.md`](live-proxy-http-request-contract.md):

- `source`
- `request_id`
- `correlation_id`
- `transport`
- `method`
- `authority`
- `path`
- `headers`
- `body_class`
- `auth_hint`
- `mode`

### Downstream outputs from session correlation

The correlation stage is expected to add:

- `session_id`
- `agent_id`
- `workspace_id`
- `provider_hint`
- `correlation_reason`
- `correlation_status`

### Downstream outputs from semantic conversion

The semantic-conversion stage now defines a stable `agenta-core` live envelope around:

- `live_surface`
- `transport`
- `target_hint`
- correlated request lineage (`request_id`, `correlation_id`, `session_id`, `agent_id`, `workspace_id`)
- routing hints (`provider_hint`, `correlation_status`)
- redaction-safe request descriptors (`method`, `authority`, `path`, `headers`, `body_class`, `auth_hint`)
- `mode`
- `content_retained=false`

### Downstream outputs from policy / approval / audit

The live interception phase is expected to preserve a stable downstream surface around:

- `normalized_event`
- `policy_decision`
- `coverage_posture`
- `mode_status`
- `approval_eligibility`
- `approval_request`
- `approval_hold_allowed`
- `hold_reason`
- `wait_state`
- `coverage_gap`
- `realized_enforcement`
- `redaction_status`

## Why this split now

This keeps the next tasks cleaner:

- future runtime work can build on fixed `shadow`, `enforce_preview`, and `unsupported` semantics without rewriting upstream ownership rules or the now-connected preview policy / approval / audit reflection path

## Explicitly out of scope for P13-1

- real proxy deployment, certificate handling, browser installation, or traffic steering
- production-grade inline pause / resume / deny mechanics
- control-plane reviewer UX or reconciliation flows beyond the ownership boundary

## Related docs

- architecture overview: [`overview.md`](overview.md)
- Rust implementation direction: [`rust-implementation.md`](rust-implementation.md)
- live proxy request contract: [`live-proxy-http-request-contract.md`](live-proxy-http-request-contract.md)
- generic live action envelope: [`generic-live-action-envelope.md`](generic-live-action-envelope.md)
- generic REST live preview path: [`generic-rest-live-preview-path.md`](generic-rest-live-preview-path.md)
- provider live preview adapter boundaries: [`provider-live-preview-adapter-boundaries.md`](provider-live-preview-adapter-boundaries.md)
- live preview mode semantics: [`live-preview-mode-semantics.md`](live-preview-mode-semantics.md)
- live preview record reflection: [`live-preview-record-reflection.md`](live-preview-record-reflection.md)
- live proxy test fixtures: [`live-proxy-test-fixtures.md`](live-proxy-test-fixtures.md)
- live proxy semantic coverage matrix: [`live-proxy-coverage-matrix.md`](live-proxy-coverage-matrix.md)
- generic REST / OAuth boundary: [`generic-rest-oauth-governance-foundation.md`](generic-rest-oauth-governance-foundation.md)
- messaging / collaboration boundary: [`messaging-collaboration-governance-foundation.md`](messaging-collaboration-governance-foundation.md)
- provider abstraction foundation: [`provider-abstraction-foundation.md`](provider-abstraction-foundation.md)
- GWS API / network boundary: [`hostd-api-network-gws-poc.md`](hostd-api-network-gws-poc.md)
- GitHub semantic governance boundary: [`hostd-github-semantic-governance-poc.md`](hostd-github-semantic-governance-poc.md)
- approval / control-plane UX boundary: [`approval-control-plane-ux-foundation.md`](approval-control-plane-ux-foundation.md)
- failure posture reference: [`failure-behavior.md`](failure-behavior.md)
