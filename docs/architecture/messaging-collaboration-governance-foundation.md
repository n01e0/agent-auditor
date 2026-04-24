# messaging / collaboration governance phase boundary

This note fixes the first internal split for the repository-wide messaging / collaboration governance phase.

## Goal of P11-1

Keep the next governance layer honest about ownership before a messaging action taxonomy lands, before a provider-neutral messaging contract lands in `agenta-core`, and before Slack / Discord style collaboration actions start being evaluated directly by policy.

The immediate rule is:

- **provider-specific taxonomy** owns translating provider-native API, browser, or network hints into provider-local action candidates and the already-shared provider action identity
- **generic REST contract** owns the lower-level REST / OAuth governance surface for method / host / path / query / auth / privilege descriptors
- **messaging / collaboration taxonomy** owns the cross-provider action-family layer for collaboration semantics such as `message.send`, `channel.invite`, `permission.update`, and `file.upload`
- **messaging / collaboration contract** owns the provider-neutral action surface that later policy, approval, audit, and control-plane UX consume
- **policy** owns evaluating that messaging contract and projecting `allow` / `deny` / `require_approval` outcomes plus approval candidates
- **record** owns durable audit / approval persistence and publish fanout for messaging actions
- the shared seams are a small provider taxonomy + generic REST contract → messaging family handoff, then a small messaging contract → policy → record flow that preserves the messaging redaction rule

Unlike P10, this phase is no longer deciding only **what REST call happened**. It is deciding **what collaboration intent happened** across providers: whether an agent tried to send a message, invite a member, change a permission, or upload a file, along with the minimum redaction-safe context needed for review.

That means the generic REST layer must stop pretending that `POST /messages` is enough policy surface by itself, while the messaging layer must also stop pretending it owns provider-native route heuristics or raw content payloads. The generic REST contract remains the lower-level substrate; P11 adds the collaboration semantics above it.

The redaction rule for this phase is explicit from the start: messaging seams should carry action family, provider lineage, channel / conversation / target hints, membership / permission / file target classes, attachment-count hints, delivery-scope hints, and docs-backed auth / privilege descriptors only. Raw message bodies, rich-text content, uploaded file bytes, preview URLs, thread history, DM participant lists, secret invite links, and provider-specific opaque payloads do not cross the boundary.

## Code layout

`crates/agenta-core/src/messaging.rs`

- checked-in home for the concrete messaging / collaboration governance contract from P11-3
- provider-neutral `MessagingAction`, `MessagingActionFamily`, `DeliveryScope`, and messaging target descriptor types
- checked-in type surface that `agenta-policy`, audit records, and later provider modules can share

`cmd/agent-auditor-hostd/src/poc/messaging/`

- `contract.rs`
  - checked-in shared seams between provider taxonomy input, generic REST input, messaging-family normalization, policy projection, and record reflection
- `taxonomy.rs`
  - checked-in home for the provider-contract + generic REST → messaging-family boundary plan plus the first Slack / Discord minimal taxonomy model
- `policy.rs`
  - checked-in home for messaging-policy boundary ownership and approval projection responsibilities
- `record.rs`
  - checked-in home for messaging audit / approval reflection responsibilities
- `mod.rs`
  - bootstrap assembly and tests for the messaging / collaboration governance split

Provider-specific taxonomy remains outside this phase boundary and stays in provider modules until later migration work lands:

- Google Workspace / Gmail path: `cmd/agent-auditor-hostd/src/poc/gws/`
- GitHub path for provider-abstraction lineage only: `cmd/agent-auditor-hostd/src/poc/github/`
- next planned providers for the messaging taxonomy slice: Slack and Discord in P11-2

## Responsibility split

### Provider-specific taxonomy

Owns:

- accepting provider-native API, browser, or network hints from upstream adapters
- classifying those hints into provider-local action labels plus the shared `provider_id + action_key + target_hint` identity already fixed by P8 / P9
- attaching provider-local classifier labels, semantic surfaces, and classification rationale
- deciding provider-specific matching heuristics, route special cases, and product-surface distinctions
- handing off only redaction-safe provider action identity and target summaries downstream

Does **not** own:

- the provider-neutral messaging / collaboration contract
- cross-provider action families such as `message.send` or `channel.invite` as a shared downstream policy surface
- durable policy outcome selection or audit persistence
- storage of raw message content or file payloads in the shared messaging seam

### Generic REST contract

Owns:

- defining the lower-level REST / OAuth governance surface consumed by the messaging layer when collaboration actions still map onto API semantics
- carrying provider-neutral method / host / path / query / auth / privilege descriptors forward
- preserving provider lineage and redaction-safe target hints without re-running provider-specific classification

Does **not** own:

- deciding whether a REST action is best interpreted as `message.send`, `channel.invite`, `permission.update`, or `file.upload`
- collaboration-specific audience, membership, or attachment semantics as first-class policy families
- raw message bodies, file bytes, or thread content
- durable audit / approval persistence

### Messaging / collaboration taxonomy

Owns:

- deciding the shared collaboration action family for provider actions that map to messaging semantics
- translating provider-specific action identity plus generic REST descriptors into repository-owned collaboration families such as `message.send`, `channel.invite`, `permission.update`, and `file.upload`
- deciding whether an action is fundamentally about delivery, membership expansion, permission mutation, or file publication even when multiple lower-level REST routes can implement it
- preserving redaction-safe collaboration hints such as channel / conversation target, membership target class, permission target class, file target class, and attachment-count hints

Does **not** own:

- provider-specific route matching heuristics
- the lower-level REST / OAuth descriptors themselves
- policy outcome selection or durable record storage
- raw message content, file bytes, or participant rosters beyond redaction-safe hints

### Messaging / collaboration contract

Owns:

- defining the provider-neutral messaging governance surface consumed by downstream policy and record code
- carrying action family and redaction-safe collaboration target descriptors into policy and audit flows
- preserving provider lineage and generic REST lineage for explainability without re-running upstream classification
- fixing which messaging descriptors are governance-relevant enough to survive into approval and audit flows

Does **not** own:

- provider-specific route matching heuristics or taxonomy rules
- runtime proof that a message was actually delivered or a permission change actually propagated
- full message bodies, uploaded file bytes, or rich-content previews
- durable audit / approval persistence or operator notification fanout

### Policy

Owns:

- bridging the messaging / collaboration contract into `agenta-policy`
- evaluating collaboration actions against checked-in policy
- projecting `allow`, `deny`, and `require_approval` outcomes plus approval-request candidates
- carrying the messaging redaction contract forward into record reflection

Does **not** own:

- provider-native taxonomy heuristics
- lower-level REST normalization
- defining the messaging contract fields themselves
- durable audit or approval storage

### Record

Owns:

- appending redaction-safe messaging audit records
- appending approval requests created by approval-gated messaging actions
- reflecting policy outcomes into append-only storage and later control-plane fanout without replaying upstream taxonomy or normalization joins
- publishing enough structured detail for operators to review collaboration decisions without recovering raw content payloads

Does **not** own:

- provider taxonomy heuristics
- action-family inference logic
- policy evaluation logic
- storage or display of raw message bodies, file bytes, invite links, or full participant lists

## Boundary inputs and outputs fixed by P11-1

P11-1 does **not** fix the final Rust structs yet, but it does fix the ownership of the fields that P11-2 and P11-3 may introduce.

### Upstream inputs into the messaging-family join

From provider taxonomy and generic REST layers, the messaging phase may rely on:

- `provider_id`
- `action_key`
- `target_hint`
- `method`
- `host`
- `path_template`
- `query_class`
- `oauth_scope_labels`
- `side_effect`
- `privilege_class`
- provider-local classifier labels / reasons
- provider-local semantic surface hints

### Downstream outputs from the messaging contract

The messaging phase is expected to define a stable policy / audit surface around:

- `action_family`
- redaction-safe `channel_hint` or `conversation_hint`
- redaction-safe `target_hint`
- `delivery_scope`
- `membership_target_kind`
- `permission_target_kind`
- `file_target_kind`
- `attachment_count_hint`
- upstream provider lineage for explainability
- upstream generic REST lineage for explainability

The messaging layer may preserve provider and REST lineage, but that lineage is explanatory context, not permission to leak raw content payloads or provider-native heuristics into downstream policy.

## Why this split now

This keeps the next tasks cleaner:

- **P11-2** can define a shared messaging taxonomy for Slack / Discord style providers against a stable ownership boundary
- **P11-3** can add messaging contract types to `agenta-core` without conflating them with generic REST descriptors
- **P11-4** can evaluate provider-neutral messaging actions in `agenta-policy` without dragging route heuristics back into policy input
- **P11-5** can reflect messaging approval / deny / hold outcomes into records without replaying taxonomy joins
- **P11-6** can pin unit tests and smoke tests around one stable messaging preview contract
- **P11-7** can document the local workflow and limitations of the messaging layer without conflating it with the generic REST slice
- **P12** can build approval / control-plane UX on top of higher-level collaboration actions instead of only lower-level REST descriptors

## Explicitly out of scope for P11-1

- the concrete `agenta-core` messaging / collaboration types themselves
- the concrete Slack / Discord common taxonomy model
- the concrete `agenta-policy` input mapping for messaging actions
- durable messaging audit / approval record implementations
- live Slack / Discord interception, bot-token verification, or webhook mediation
- full message-content policy, DLP, malware scanning, or file-content inspection
- control-plane reviewer UX, reconciliation, or notification flows from P12

## Related docs

- architecture overview: [`overview.md`](overview.md)
- messaging action catalog: [`messaging-collaboration-action-catalog.md`](messaging-collaboration-action-catalog.md)
- Hermes/Discord durable audit normalization path: [`hermes-discord-durable-audit-normalization-path.md`](hermes-discord-durable-audit-normalization-path.md)
- approval / control-plane UX boundary: [`approval-control-plane-ux-foundation.md`](approval-control-plane-ux-foundation.md)
- local runbook: [`../runbooks/messaging-collaboration-governance-local.md`](../runbooks/messaging-collaboration-governance-local.md)
- known constraints: [`messaging-collaboration-governance-known-constraints.md`](messaging-collaboration-governance-known-constraints.md)
- generic REST / OAuth boundary: [`generic-rest-oauth-governance-foundation.md`](generic-rest-oauth-governance-foundation.md)
- generic REST / OAuth known constraints: [`generic-rest-oauth-governance-known-constraints.md`](generic-rest-oauth-governance-known-constraints.md)
- provider abstraction foundation: [`provider-abstraction-foundation.md`](provider-abstraction-foundation.md)
- GitHub semantic governance boundary: [`hostd-github-semantic-governance-poc.md`](hostd-github-semantic-governance-poc.md)
- policy contract notes: [`../policies/rego-contract.md`](../policies/rego-contract.md)
