# provider abstraction phase boundary

This note fixes the first internal split for the repository-wide provider abstraction phase after the initial Google Workspace slice.

## Goal of P8-1

Keep the provider abstraction work honest about ownership before a shared provider contract lands in `agenta-core`, before docs-backed provider metadata lands, before GWS migrates onto the shared shape, and before GitHub is introduced as the next provider candidate.

The immediate rule is:

- **provider-specific taxonomy** owns translating provider-native hints into provider-local action candidates
- **provider contract** owns the provider-neutral action identity that later policy and audit code consume
- **provider metadata** owns docs-backed method / resource / side effect / scope / privilege descriptors keyed by the shared action identity
- the shared seams are a small taxonomy → contract handoff and a small contract → metadata join that both preserve the same redaction rule

Unlike the earlier GWS-only phase, this boundary is explicitly cross-provider from the start. `agenta-core` should stop assuming Google-specific labels are the permanent policy surface, while provider adapters should stop owning documentation catalogs that future providers need to share.

The redaction rule for this phase is also explicit from the start: provider abstraction seams should carry action identity, target hints, and docs-backed descriptors only. Raw provider payloads, message bodies, Drive file contents, issue bodies, pull-request diffs, and similar high-retention data do not cross the boundary.

## Code layout

`crates/agenta-core/src/provider.rs`

- boundary plan for the provider abstraction phase
- shared labels for provider-specific taxonomy, provider contract, and provider metadata ownership
- concrete provider-common contract types from P8-2 (`provider_id + action_key + target_hint`)
- concrete provider-common metadata types from P8-3 (`method`, `canonical_resource`, `side_effect`, `oauth_scopes`, `privilege_class`)

Provider-specific taxonomy remains in provider adapters and PoC modules until migration work lands:

- current motivating implementation: `cmd/agent-auditor-hostd/src/poc/gws/`
- next provider candidate fixed by the roadmap: GitHub
- initial GitHub candidate action and metadata catalog: [`provider-abstraction-github-candidate-catalog.md`](provider-abstraction-github-candidate-catalog.md)

## Responsibility split

### Provider-specific taxonomy

Owns:

- accepting provider-native API, browser, or network hints from upstream adapters
- mapping those hints into provider-local action labels and redaction-safe target hints
- attaching provider-local classifier labels and classification rationale
- deciding provider-specific matching heuristics for GWS today and GitHub next
- handing off `provider_id` plus `provider_action_label` without defining the shared policy surface

Does **not** own:

- the provider-neutral contract consumed by `agenta-core`
- the docs-backed method / resource / side effect / scope catalog
- `agenta-policy` input generalization
- audit posture or privilege metadata catalogs

### Provider contract

Owns:

- defining the minimal provider-neutral action identity shared across providers
- fixing the downstream handoff around `provider_id + action_key + target_hint`
- giving `agenta-core` and later `agenta-policy` a stable surface that no longer depends on GWS-only labels
- carrying redaction-safe action identity without reusing provider-native classification heuristics as the contract itself

Does **not** own:

- provider-specific classification rules
- official method or auth documentation catalogs
- OAuth scope or privilege descriptors as standalone metadata
- provider runtime adapters or interception mechanics

### Provider metadata

Owns:

- attaching docs-backed `method`, `canonical_resource`, `side_effect`, `oauth_scopes`, and `privilege_class` descriptors to the shared contract
- keying metadata by the shared `provider_id + action_key` identity instead of provider-native transport hints
- acting as the descriptive catalog for policy, audit, docs, and future UI work
- preserving the redaction rule while making provider actions explainable without raw payload retention

Does **not** own:

- provider-specific matching heuristics
- mutating the shared provider contract identity
- deciding allow / deny / require-approval outcomes
- introducing a full provider runtime implementation

## Why this split now

This keeps the next tasks cleaner:

- **P8-2** can add the shared provider contract in `agenta-core` against a stable ownership boundary
- **P8-3** can add provider metadata without re-litigating who owns docs-backed descriptors
- **P8-4** can migrate GWS semantic actions onto the shared contract without moving metadata ownership back into the classifier
- **P8-5** can generalize `agenta-policy` input around provider + action instead of GWS-only action labels
- **P8-6** can fix GitHub candidate actions and metadata shape in docs without pretending the full provider runtime exists yet

## Explicitly out of scope for P8-1

- the concrete shared provider contract types themselves
- the concrete shared provider metadata schema itself
- the GWS migration onto the shared contract
- the `agenta-policy` input migration
- the concrete GitHub provider implementation
- live request interception or provider-specific execution control

## Related docs

- architecture overview: [`overview.md`](overview.md)
- local runbook: [`../runbooks/provider-abstraction-foundation-local.md`](../runbooks/provider-abstraction-foundation-local.md)
- known constraints: [`provider-abstraction-known-constraints.md`](provider-abstraction-known-constraints.md)
- GWS phase boundary: [`hostd-api-network-gws-poc.md`](hostd-api-network-gws-poc.md)
- GWS action catalog: [`hostd-api-network-gws-action-catalog.md`](hostd-api-network-gws-action-catalog.md)
- policy contract notes: [`../policies/rego-contract.md`](../policies/rego-contract.md)
- GitHub candidate catalog: [`provider-abstraction-github-candidate-catalog.md`](provider-abstraction-github-candidate-catalog.md)
- roadmap mirror: [`../roadmaps/provider-abstraction-foundation-tasklist.md`](../roadmaps/provider-abstraction-foundation-tasklist.md)
