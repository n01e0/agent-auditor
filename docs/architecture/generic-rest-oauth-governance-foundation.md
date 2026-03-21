# generic REST / OAuth governance phase boundary

This note fixes the first internal split for the repository-wide generic REST / OAuth governance phase.

## Goal of P10-1

Keep the next governance layer honest about ownership before a generic REST action contract lands in `agenta-core`, before `agenta-policy` starts evaluating provider-neutral REST actions directly, and before messaging / collaboration providers try to reuse the same surface.

The immediate rule is:

- **provider-specific taxonomy** owns translating provider-native API, browser, or network hints into provider-local action candidates and the already-shared provider action identity
- **provider metadata** owns the docs-backed method / resource / auth-label / side-effect / privilege descriptors keyed by the shared `provider_id + action_key` identity
- **generic REST contract** owns the provider-neutral REST / OAuth governance surface that later policy, approval, audit, and messaging-provider work consume
- **policy** owns evaluating that generic REST contract and projecting `allow` / `deny` / `require_approval` outcomes plus approval candidates
- **record** owns durable audit / approval persistence and publish fanout
- the shared seams are a small provider taxonomy → shared provider contract handoff, a docs-backed provider contract + metadata → generic REST contract join, and a small generic REST contract → policy → record flow that all preserve the same redaction rule

Unlike P8 and P9, this phase is no longer deciding only **which provider action happened**. It is deciding **which cross-provider REST governance facts** should survive downstream: HTTP method, authority / host, canonical path template, query-shape classification, auth scope labels, side effect, privilege class, and redaction-safe target hints.

That means provider adapters must stop treating their own taxonomy as the long-term policy surface, while the new generic REST layer must also stop pretending it owns provider-native heuristics. The shared provider contract from P8 stays the join key; P10 adds the next abstraction above it.

The redaction rule for this phase is explicit from the start: generic REST / OAuth seams should carry route templates, host / authority labels, query classes, action identity, target hints, and docs-backed auth / risk descriptors only. Raw request bodies, response bodies, message text, file bytes, diff hunks, token values, signed URLs, full query strings, and provider-specific opaque payloads do not cross the boundary.

## Code layout

`crates/agenta-core/src/rest.rs`

- checked-in home for the concrete generic REST / OAuth governance contract from P10-2
- provider-neutral `GenericRestAction`, `RestHost`, `PathTemplate`, and `QueryClass` types
- checked-in type surface that `agenta-policy`, audit records, and later provider modules can share

`cmd/agent-auditor-hostd/src/poc/rest/`

- `contract.rs`
  - checked-in shared seams between provider metadata / provider action input, generic REST normalization, policy projection, and record reflection
- `normalize.rs`
  - checked-in home for the provider-contract + metadata → generic REST contract boundary plan
- `policy.rs`
  - checked-in home for generic REST `agenta-policy` boundary ownership and approval projection responsibilities
- `record.rs`
  - checked-in home for append-only audit / approval reflection responsibilities after generic REST policy evaluation
- `mod.rs`
  - bootstrap assembly and tests for the generic REST / OAuth governance split

Provider-specific taxonomy remains outside this phase boundary and stays in provider modules until later migration work lands:

- Google Workspace path: `cmd/agent-auditor-hostd/src/poc/gws/`
- GitHub path: `cmd/agent-auditor-hostd/src/poc/github/`
- next planned consumers of the generic REST layer: messaging / collaboration providers in P11

## Responsibility split

### Provider-specific taxonomy

Owns:

- accepting provider-native API, browser, or network hints from upstream adapters
- classifying those hints into provider-local action labels plus the shared `provider_id + action_key + target_hint` identity already fixed by P8 / P9
- attaching provider-local classifier labels, semantic surfaces, and classification rationale
- deciding provider-specific matching heuristics, route special cases, and product-surface distinctions
- handing off only redaction-safe provider action identity and target summaries downstream

Does **not** own:

- the provider-neutral generic REST / OAuth contract
- cross-provider host / path / query-class semantics as a downstream policy surface
- docs-backed scope / privilege / side-effect catalogs as mutable classifier state
- policy outcome selection or durable audit persistence

### Provider metadata

Owns:

- curating docs-backed method, canonical resource, auth-label, side-effect, and privilege descriptors keyed by shared provider action identity
- translating provider-specific docs vocabulary into stable repository-owned metadata labels before the generic REST join
- acting as the descriptive catalog that generic REST normalization, policy, audit, docs, and later UI work can join against without re-running taxonomy
- preserving the same redaction rule while keeping provider auth / permission facts explainable without payload retention

Does **not** own:

- provider-native request matching or taxonomy heuristics
- mutating the shared provider contract identity
- deciding the final generic REST event shape by itself
- policy outcome selection or durable record storage

### Generic REST contract

Owns:

- defining the provider-neutral REST / OAuth governance surface consumed by downstream policy and record code
- translating shared provider action identity plus docs-backed metadata into stable generic fields such as `method`, `host`, `path_template`, `query_class`, `oauth_scope_labels`, `side_effect`, and `privilege_class`
- preserving redaction-safe target hints and provider lineage without re-running provider-specific classification
- becoming the common contract that later messaging / collaboration providers can reuse when their operations still map onto REST + OAuth semantics
- fixing which REST / OAuth descriptors are governance-relevant enough to survive into audit and approval flows

Does **not** own:

- provider-specific matching heuristics or semantic-taxonomy rules
- live token inspection, delegated-subject verification, or runtime proof that a granted scope was really present
- provider-specific UI semantics such as `message.send` or `channel.invite` as first-class cross-provider action families
- durable audit / approval persistence or operator-notification fanout

### Policy

Owns:

- bridging the generic REST contract into `agenta-policy`
- evaluating generic REST / OAuth actions against checked-in Rego policy
- projecting `allow`, `deny`, and `require_approval` outcomes plus approval-request candidates
- carrying the generic REST redaction contract forward into record reflection

Does **not** own:

- provider-native taxonomy heuristics
- provider metadata catalog curation
- defining the generic REST contract fields themselves
- durable audit or approval storage

### Record

Owns:

- appending redaction-safe generic REST audit records
- appending approval requests created by approval-gated generic REST actions
- reflecting policy outcomes into append-only storage and later control-plane fanout without replaying provider taxonomy or metadata joins
- publishing enough structured detail for operators to review decisions without recovering raw payloads

Does **not** own:

- provider taxonomy heuristics
- metadata catalog curation
- policy evaluation logic
- storage or display of raw request / response payloads, token values, message bodies, file bytes, or full query strings

## Boundary inputs and outputs fixed by P10-1

P10-1 does **not** fix the final Rust structs yet, but it does fix the ownership of the fields that P10-2 may introduce.

### Upstream inputs into the generic REST join

From the shared provider contract and provider metadata layers, the generic REST phase may rely on:

- `provider_id`
- `action_key`
- `target_hint`
- docs-backed HTTP method labels
- docs-backed canonical resource / path templates
- docs-backed auth-label / OAuth-scope labels
- docs-backed side-effect labels
- docs-backed privilege descriptors

### Downstream outputs from the generic REST contract

The generic REST phase is expected to define a stable policy / audit surface around:

- `method`
- `host` or authority label
- `path_template`
- `query_class`
- `oauth_scope_labels`
- `side_effect`
- `privilege_class`
- redaction-safe target / resource hints
- upstream provider lineage for explainability

The generic REST layer may preserve provider lineage, but provider lineage is explanatory context, not permission to leak provider-native heuristics or raw payloads into downstream policy.

## Why this split now

This keeps the next tasks cleaner:

- **P10-2** can add generic REST contract types to `agenta-core` against a stable ownership boundary
- **P10-3** can generalize `agenta-policy` around cross-provider REST / OAuth descriptors without dragging provider taxonomy back into policy input
- **P10-4** can reflect generic REST approval / deny / hold outcomes into records without re-running provider-specific joins
- **P10-5** can pin unit tests and smoke tests around one stable generic REST preview contract
- **P10-6** can document the local workflow and constraints of the generic REST layer without conflating it with provider-specific taxonomy work
- **P11** can add messaging / collaboration governance on top of the generic REST contract where REST / OAuth semantics still apply, while keeping messaging-specific action families separate from the lower-level REST seam

## Explicitly out of scope for P10-1

- the concrete `agenta-core` generic REST / OAuth types themselves
- the concrete `agenta-policy` input mapping for generic REST actions
- durable generic REST audit / approval record implementations
- live inline interception, token introspection, or delegated-subject verification
- GraphQL-, webhook-, or UI-only governance shapes that do not map cleanly onto the generic REST contract
- messaging / collaboration provider taxonomy such as `message.send`, `channel.invite`, `permission.update`, or `file.upload`

## Related docs

- architecture overview: [`overview.md`](overview.md)
- local runbook: [`../runbooks/generic-rest-oauth-governance-local.md`](../runbooks/generic-rest-oauth-governance-local.md)
- known constraints: [`generic-rest-oauth-governance-known-constraints.md`](generic-rest-oauth-governance-known-constraints.md)
- provider abstraction foundation: [`provider-abstraction-foundation.md`](provider-abstraction-foundation.md)
- provider abstraction known constraints: [`provider-abstraction-known-constraints.md`](provider-abstraction-known-constraints.md)
- GitHub semantic governance boundary: [`hostd-github-semantic-governance-poc.md`](hostd-github-semantic-governance-poc.md)
- GWS API / network boundary: [`hostd-api-network-gws-poc.md`](hostd-api-network-gws-poc.md)
- GWS action catalog: [`hostd-api-network-gws-action-catalog.md`](hostd-api-network-gws-action-catalog.md)
- GitHub candidate catalog: [`provider-abstraction-github-candidate-catalog.md`](provider-abstraction-github-candidate-catalog.md)
- policy contract notes: [`../policies/rego-contract.md`](../policies/rego-contract.md)
