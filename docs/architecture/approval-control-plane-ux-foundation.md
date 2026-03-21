# approval / control-plane UX phase boundary

This note fixes the first internal split for the repository-wide approval / control-plane UX phase.

## Goal of P12-1

Keep the next operator-facing slice honest about ownership before approval queue models, decision summaries, rationale capture, stale/drift recovery, notification improvements, and control-plane reconciliation logic land.

The immediate rule is:

- **upstream governance layers** own producing normalized events, policy decisions, approval requests, enforcement outcomes, and append-only audit records
- **review queue** owns turning that upstream record set into stable operator work items, pending/reviewed state, and explicit waiting / stale / degraded markers
- **reviewer experience** owns the operator-facing summary of what is being reviewed, what the likely impact is, and what approve / deny / defer actions should capture
- **policy explainability** owns rendering the redaction-safe “why” behind a decision by using stored rule ids, reasons, severities, tags, lineage, and requester context without re-running provider taxonomy or exposing raw payloads
- **ops hardening** owns stale-state detection, drift markers, recovery / reconciliation rules, and explicit waiting states such as “decision recorded but downstream completion still pending”
- the shared seam is a small approval / audit record → queue / explainability / decision-capture / reconciliation flow that preserves the same redaction rule already fixed by P10 and P11

Unlike P10 and P11, this phase is no longer deciding **what action happened** or **what policy returned**. It is deciding **how humans consume, explain, and operate on the already-recorded approval state** without collapsing policy, provider taxonomy, and runtime recovery into one blurry control-plane layer.

The redaction rule for this phase is explicit from the start: control-plane UX may use request summaries, target hints, severity, reviewer hints, rule ids, decision reasons, tags, upstream provider / generic REST / messaging lineage, coverage gaps, timestamps, and requester context. It must not depend on raw message bodies, uploaded bytes, secret values, full request bodies, token material, invite links, participant rosters, or provider-specific opaque payloads.

## Code layout

The checked-in substrate that P12 builds on already exists here:

`crates/agenta-core/src/lib.rs`

- checked-in home for shared `ApprovalRequest`, `ApprovalDecisionRecord`, `PolicyDecision`, `RequesterContext`, and `EnforcementInfo` types
- existing schema surface that control-plane UX must consume instead of inventing a second approval model

`cmd/agent-auditor-hostd/src/poc/`

- existing repository-owned producers for approval and audit artifacts across filesystem, secret, GWS, generic REST, GitHub, and messaging slices
- the source of the append-only preview records that P12 will summarize, reconcile, and eventually present to operators

P12 should sit **above** those producer paths. It should not move queue semantics, reviewer UX, or reconciliation rules back into provider-specific taxonomy / policy / record modules.

The concrete control-plane implementation home can still land later, but the ownership boundary from this note assumes a control-plane-oriented surface such as a future `agent-auditor-controld` / `cmd/agent-auditor-controld/` rather than more logic embedded inside provider-specific PoC modules.

## Responsibility split

### Upstream governance layers

Own:

- producing normalized `EventEnvelope` records, `PolicyDecision` outputs, `ApprovalRequest` records, and reflected enforcement metadata
- preserving redaction-safe lineage from provider taxonomy, generic REST normalization, messaging taxonomy, or earlier runtime seams
- carrying forward the exact rule id, reason, severity, tags, reviewer hint, approval scope, TTL, requester context, and enforcement metadata that downstream UX may need
- appending audit / approval artifacts without depending on operator-facing queue semantics

Do **not** own:

- approval queue ordering, inbox semantics, or operator status labels
- reviewer-facing wording beyond the stored redaction-safe summary / rationale fields
- stale-state, drift, or reconciliation policy for control-plane workflows
- notification fanout, status surfaces, or operator UX concerns

### Review queue

Owns:

- turning append-only approval / audit state into explicit operator work items such as pending, approved, denied, expired, stale, reconciled, or waiting-for-downstream-completion
- deciding which fields are stable enough to sort, filter, group, and de-duplicate reviewable work without re-running upstream policy or taxonomy
- preserving review identity around `approval_id`, `event_id`, `session_id`, timestamps, TTL, severity, and current status
- surfacing when multiple records describe the same approval flow so the operator sees one coherent queue item instead of raw record fragments

Does **not** own:

- provider-specific action classification
- policy evaluation or risk scoring
- reviewer rationale authoring rules beyond capturing what the operator supplied
- low-level storage durability mechanics or audit integrity chaining

### Reviewer experience

Owns:

- presenting a compact operator-facing decision surface for approve / deny / defer / inspect actions
- showing the action summary, target hints, requester context, policy scope, TTL, reviewer hint, and downstream impact summary in a consistent shape
- capturing reviewer identity, reviewer note, and final outcome without mutating the upstream policy explanation itself
- distinguishing “can decide now” from “blocked by stale data / degraded reconciliation / missing downstream state” in a way that an operator can act on

Does **not** own:

- inventing new policy decisions that were not produced upstream
- reclassifying provider actions or reading raw provider payloads to make UX nicer
- runtime pause / resume or provider-side execution control
- external notification transport semantics, except as a consumer of queue state later in P12-4

### Policy explainability

Owns:

- rendering the stored policy outcome into a reviewer-friendly explanation using rule ids, reason strings, severity, tags, reviewer hint, requester context, and redaction-safe lineage
- preserving enough lineage for an operator to understand whether a queue item came from filesystem, secret, GWS, generic REST, GitHub, or messaging work without re-running upstream normalization
- explaining the difference between intended `allow` / `hold` / `deny` posture and validated runtime enforcement where the docs already require that distinction
- making coverage gaps, fail-open fallback, and “preview only” posture visible when the runtime has not actually guaranteed a pause or block

Does **not** own:

- editing policy bundles or choosing policy outcomes
- storing or retrieving raw content that upstream redaction already excluded
- becoming a second taxonomy layer for provider-specific heuristics
- conflating operator explanation with actual execution guarantees

### Ops hardening

Owns:

- defining how stale approval items, expired TTLs, missing downstream completion, drift between approval records and audit state, and restart / replay recovery should surface to operators
- fixing explicit recovery / reconciliation states so the control plane can tell “pending reviewer action” apart from “decision recorded but downstream action still unresolved” and “queue item no longer matches durable state”
- defining idempotent re-materialization rules for queue state from append-only approval / audit inputs
- surfacing waiting states such as `waiting_merge` or downstream-completion-pending as control-plane semantics instead of burying them in ad hoc runner behavior

Does **not** own:

- provider-specific execution retry logic
- GitHub / Slack / Discord / GWS runtime adapters themselves
- the underlying append-only audit store implementation
- operator-facing policy explanation text beyond the state / recovery semantics it needs to describe

## Boundary inputs and outputs fixed by P12-1

P12-1 does **not** fix the final Rust structs yet, but it does fix the ownership of the fields and artifacts that later P12 tasks may introduce.

### Upstream inputs into the approval / control-plane layer

From the already-existing governance and enforcement layers, the control-plane UX phase may rely on:

- `approval_id`
- `event_id`
- `session_id`
- request summary, target hint, action verb, action class, and redaction-safe attributes
- policy rule id, severity, reason, scope, TTL, and reviewer hint
- requester context such as agent reason and optional human request
- enforcement status, directive, approval linkage, expiry, and coverage-gap metadata
- timestamps and current approval status
- upstream lineage that explains whether the item came from filesystem, secret, GWS, generic REST, GitHub, messaging, or later provider families

### Downstream outputs from the approval / control-plane layer

The control-plane UX phase is expected to define a stable operator surface around:

- queue-item status and grouping semantics
- reviewer-facing decision summaries
- rationale-capture / decision-capture semantics
- explainability summaries derived from stored policy metadata
- stale / expired / drift / reconciliation markers
- explicit waiting-state vocabulary for downstream completion or merge-like follow-up
- notification-ready and status-ready summaries that later delivery code can consume without re-reading raw records

The control-plane layer may preserve upstream lineage, but lineage is explanatory context, not permission to re-open the redaction boundary.

## Why this split now

This keeps the next tasks cleaner:

- **P12-2** can define a minimal approval queue / decision summary / rationale-capture model against a stable ownership boundary
- **P12-3** can fix stale-state, drift, recovery, and `waiting_merge` semantics without reaching back into provider-specific policy or record code
- **P12-4** can add notification / status / reconciliation improvements and tests on top of a stable control-plane vocabulary
- **P12-5** can document runbooks and known constraints for the operator-facing approval layer without conflating them with upstream governance phases
- later runtime work can add real provider resume / cancel paths without breaking the operator-facing control-plane seam defined here

## Explicitly out of scope for P12-1

- redefining the existing `ApprovalRequest`, `PolicyDecision`, or `EventEnvelope` schema types
- provider-specific taxonomy or policy changes for GWS, GitHub, Slack, Discord, filesystem, process, or secrets
- durable multi-tenant SaaS control-plane architecture
- full notification delivery integrations or paging-policy design
- live provider resume / cancel / replay mechanics after approval resolution
- operator authentication / authorization policy for a production control plane
- automatic policy-authoring or policy-learning UX

## Related docs

- architecture overview: [`overview.md`](overview.md)
- messaging / collaboration governance boundary: [`messaging-collaboration-governance-foundation.md`](messaging-collaboration-governance-foundation.md)
- generic REST / OAuth governance boundary: [`generic-rest-oauth-governance-foundation.md`](generic-rest-oauth-governance-foundation.md)
- hostd enforcement foundation: [`hostd-enforcement-foundation.md`](hostd-enforcement-foundation.md)
- failure behavior policy: [`failure-behavior.md`](failure-behavior.md)
- messaging known constraints: [`messaging-collaboration-governance-known-constraints.md`](messaging-collaboration-governance-known-constraints.md)
- generic REST known constraints: [`generic-rest-oauth-governance-known-constraints.md`](generic-rest-oauth-governance-known-constraints.md)
- hostd enforcement known constraints: [`hostd-enforcement-known-constraints.md`](hostd-enforcement-known-constraints.md)
- policy contract notes: [`../policies/rego-contract.md`](../policies/rego-contract.md)
- Rust implementation notes: [`rust-implementation.md`](rust-implementation.md)
