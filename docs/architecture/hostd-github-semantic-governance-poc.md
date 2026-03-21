# hostd GitHub semantic governance phase boundary

This note fixes the first internal split for the `agent-auditor-hostd` GitHub semantic-governance slice.

## Goal of P9-1

Keep the first GitHub governance slice honest about ownership before high-risk GitHub action taxonomy, docs-backed metadata joins, normalized `agenta-core` events, policy wiring, and durable audit / approval storage land.

The immediate rule is:

- **action_taxonomy** owns turning upstream GitHub API- and browser-origin governance hints into redaction-safe GitHub semantic action candidates
- **provider_metadata** owns docs-backed method / resource / side effect / auth-label / privilege descriptors keyed by the shared `provider_id + action_key` contract
- **policy** owns `agenta-core` normalization, metadata join, `agenta-policy` bridging, and approval-gate projection
- **record** owns durable audit / approval persistence and publish fanout
- the shared seams are a small action_taxonomy → policy contract, a docs-backed provider_metadata → policy join, and a small policy → record contract that all preserve the same GitHub redaction rule

Unlike the earlier API / network GWS phase, this boundary does **not** add a standalone session-linkage stage. GitHub governance inputs are expected to arrive from upstream adapters after session attribution or equivalent request ownership is already available. P9-1 is only fixing the GitHub-specific split after that upstream ownership exists.

The redaction rule for this phase is explicit from the start: raw GitHub request or response payloads, issue bodies, pull-request bodies, diff hunks, workflow YAML bodies, and secret values must not cross the GitHub governance seams. The GitHub layer should operate on method / route hints, semantic action labels, target hints, and docs-backed metadata rather than arbitrary payload capture.

## Code layout

`cmd/agent-auditor-hostd/src/poc/github/`

- `contract.rs`
  - shared seams between action_taxonomy → policy, provider_metadata → policy, and policy → record
  - supported GitHub signal-source labels, semantic surfaces, planned high-risk governance action labels, and redaction contract
- `taxonomy.rs`
  - GitHub governance taxonomy boundary plan
  - checked-in home for GitHub high-risk action matching from API / browser request hints
- `metadata.rs`
  - docs-backed GitHub metadata boundary plan
  - current home for the ownership rule that method / canonical resource / side effect / auth labels / privilege class stay outside taxonomy and record
- `policy.rs`
  - normalization + metadata join + policy bridge plan after taxonomy
  - future home for `agenta-core` GitHub governance event shaping and `agenta-policy` evaluation
- `record.rs`
  - audit / approval record plan after policy evaluation
  - future home for append-only storage and publish fanout
- `mod.rs`
  - assembles the GitHub semantic-governance boundary plan and tests the split

## Responsibility split

### Action taxonomy

Owns:

- accepting GitHub API- and browser-origin governance hints after upstream session attribution is already done
- classifying redaction-safe request context into GitHub semantic action candidates and target hints
- attaching semantic surface labels, classifier labels, and rationale without joining docs-backed provider metadata
- handing off `provider_id`, `action_key`, `target_hint`, and classifier-owned context downstream

Does **not** own:

- docs-backed method / canonical resource / scope catalogs
- `agenta-core` event normalization
- Rego / `agenta-policy` evaluation
- durable audit or approval persistence

### Provider metadata

Owns:

- curating docs-backed GitHub method, canonical resource, side effect, auth-label, and privilege descriptors keyed by `provider_id + action_key`
- keeping GitHub auth-label vocabulary aligned with the shared provider metadata contract from P8
- acting as the descriptive catalog that policy, audit, docs, and later UI work can join against without re-running taxonomy
- fixing the first six high-risk GitHub governance entries in [`provider-abstraction-github-candidate-catalog.md`](provider-abstraction-github-candidate-catalog.md)

Does **not** own:

- live GitHub request matching or taxonomy heuristics
- session attribution
- policy outcome selection
- durable record storage

### Policy

Owns:

- normalizing classified GitHub governance candidates toward `agenta-core`
- joining docs-backed provider metadata onto shared GitHub action identity before evaluation
- bridging normalized GitHub governance actions into `agenta-policy`
- projecting `allow` / `deny` / `require_approval` plus approval-request candidates for recording
- carrying the GitHub redaction contract forward into the record stage

Does **not** own:

- upstream session attribution or GitHub request capture
- GitHub taxonomy heuristics
- curating the docs-backed metadata catalog
- durable audit or approval storage

### Record

Owns:

- appending redaction-safe GitHub governance audit records
- appending approval requests created by approval-gated GitHub governance actions
- publishing recorded artifacts to structured logs and later control-plane sinks

Does **not** own:

- GitHub taxonomy heuristics
- metadata catalog curation
- policy evaluation or approval decision logic
- recovering raw GitHub payloads, diff hunks, workflow YAML bodies, or secret values for storage or display

## Supported boundary labels in P9-1

The boundary is intentionally small but explicit about the labels it will carry forward:

- signal sources:
  - `api_observation`
  - `browser_observation`
- semantic surfaces:
  - `github`
  - `github.repos`
  - `github.branches`
  - `github.actions`
  - `github.pulls`

These are boundary labels, not the full long-term runtime. P9-1 fixed the first high-risk GitHub governance candidate set, and P9-2 now implements them through the classify seam:

- `repos.update_visibility`
- `branches.update_protection`
- `actions.workflow_dispatch`
- `actions.runs.rerun`
- `pulls.merge`
- `actions.secrets.create_or_update`

The earlier [`provider-abstraction-github-candidate-catalog.md`](provider-abstraction-github-candidate-catalog.md) still owns the shared docs-backed metadata shape. This GitHub governance boundary is narrower and more operational: it keeps high-risk GitHub semantic taxonomy, metadata join, policy, and record responsibilities separate before runtime logic lands.

Current checked-in taxonomy coverage stays redaction-safe:

- `repos.update_visibility` currently requires a redaction-safe visibility target hint in addition to the repository mutation route, because the bare `PATCH /repos/{owner}/{repo}` path alone is not specific enough
- the other five supported actions classify directly from method + GitHub route hints, with browser-origin signals allowed to reuse upstream route-template hints instead of exposing raw page payloads

## Why this split now

This keeps the next tasks cleaner:

- **P9-2** can implement high-risk GitHub action taxonomy against a stable upstream seam
- **P9-3** fixes the first docs-backed GitHub metadata catalog without owning request matching or audit persistence
- **P9-4 / P9-5** can normalize and evaluate GitHub governance actions against stable taxonomy and metadata seams
- **P9-6** can reflect decisions into durable records without reaching back into taxonomy or metadata curation

## Explicitly out of scope for P9-1

- concrete GitHub API interception or browser instrumentation details
- the high-risk GitHub action taxonomy implementation itself
- concrete `agenta-core` GitHub governance event normalization
- concrete `agenta-policy` GitHub policy evaluation
- durable audit / approval persistence implementation
- runtime proof that a live token carried the documented auth labels
- operator runbook / known-constraints docs for this GitHub slice

## Related docs

- provider abstraction foundation: [`provider-abstraction-foundation.md`](provider-abstraction-foundation.md)
- GitHub candidate catalog: [`provider-abstraction-github-candidate-catalog.md`](provider-abstraction-github-candidate-catalog.md)
- architecture overview: [`overview.md`](overview.md)
- product requirements: [`../PRD.md`](../PRD.md)
- coverage matrix: [`coverage-matrix.md`](coverage-matrix.md)
- shared provider contract and metadata types: [`../../crates/agenta-core/src/provider.rs`](../../crates/agenta-core/src/provider.rs)
- GWS phase boundary reference: [`hostd-api-network-gws-poc.md`](hostd-api-network-gws-poc.md)
