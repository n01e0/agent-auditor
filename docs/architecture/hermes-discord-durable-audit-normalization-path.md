# Hermes / Discord durable audit normalization path

This note fixes the **minimum non-fixture normalization path** from one real Hermes-driven Discord request to one durable audit record on the remote audit boundary.

The purpose of P19-8 is intentionally narrow:

- choose the first Discord request shape that the repository should carry from real ingress into durable audit
- keep the existing redaction-safe live-envelope and messaging-contract boundaries intact where they are already good enough
- make explicit which live lineage fields must survive normalization so later local inspection can distinguish fixture preview, observed request, and validated observation honestly
- give P19-9 through P19-12 one concrete implementation target instead of a vague "Discord support" bucket

This task is a design note, not a broad provider implementation.

## chosen first path

The first real Hermes/Discord path should be:

```text
Hermes runtime
  -> proxy-captured Discord API request
  -> remote observed-runtime ingress acceptance
  -> session-correlated live envelope
  -> Discord message-send semantic conversion
  -> messaging policy / record reflection
  -> durable audit append
```

The concrete first request is:

- provider: `discord`
- route: `POST /api/v10/channels/{channel_id}/messages`
- semantic action: `channels.messages.create`
- messaging family: `message.send`

## why this route goes first

`channels.messages.create` is the narrowest honest first path because:

- the route itself carries the redaction-safe channel identity in the URL, so the path does not need request-body recovery to produce a safe `target_hint`
- the existing live preview adapter already knows how to classify this route into the checked-in messaging taxonomy
- the shared messaging contract already has the right downstream vocabulary for `message.send`
- the resulting durable audit record is useful even before richer Discord coverage lands

This path is therefore strong enough to prove **observed request -> durable audit record** without pretending the repository already supports every Discord action.

## explicit non-goals for the first path

P19-8 does **not** require the first path to prove:

- message edit, reaction, typing, thread lifecycle, or moderation coverage
- validated observation for Discord
- inline hold/deny enforcement on live Discord traffic
- raw message-body retention, embed retention, attachment-byte retention, or roster capture
- a Hermes-specific provider contract below the live-ingress/session boundary

Those belong to later tasks.

## core rule

The minimal path should reuse the existing checked-in boundaries instead of inventing a Discord-only side channel.

That means:

- `GenericLiveActionEnvelope` stays the live ingress payload
- session ownership still comes from the observed-runtime/session-correlation seam
- provider route matching stays in `live_proxy/messaging.rs`
- collaboration-family mapping stays in `poc/messaging/taxonomy.rs`
- policy stays in `poc/messaging/policy.rs`
- record reflection stays in `poc/messaging/record.rs`
- durable append stays in `poc/messaging/persist.rs` plus the shared remote durable-store path

The new work for the Hermes/Discord path belongs in the **join between correlated live ingress and the existing messaging policy/record flow**, not in a parallel record pipeline.

## required stage split

### 1. live ingress acceptance

Already owned by the remote ingress/session path:

- `live_proxy/remote_ingress.rs`
- `live_proxy/session_correlation.rs`

This stage owns:

- boundary-crossing receipt from the Hermes-side proxy
- stable `request_id` deduplication
- session / agent / workspace lineage
- non-fixture provenance

This stage must not decide messaging semantics.

### 2. Discord live semantic conversion

Reuse the checked-in Discord route matcher in:

- `live_proxy/messaging.rs`

For the first path, the only live route that must graduate into durable audit is:

- `POST /api/v10/channels/{channel_id}/messages`

The output should still be the existing `ClassifiedMessagingAction` shape for the provider/messaging seam.

### 3. observed-messaging wrapper

The missing join is a small live-runtime wrapper that pairs live lineage with the existing messaging classification.

Introduce a live-path wrapper owned under `cmd/agent-auditor-hostd/src/poc/live_proxy/`:

- recommended home: `messaging_observed.rs`

Minimum logical shape:

```rust
ObservedMessagingAction {
    correlated: CorrelatedLiveRequest,
    classified: ClassifiedMessagingAction,
}
```

Reason for the wrapper:

- `ClassifiedMessagingAction` is the provider-neutral messaging contract and should stay focused on collaboration semantics
- `request_id`, `correlation_id`, ingress provenance, and session-correlation status are live-observation facts, not messaging-family facts
- keeping those fields in a wrapper avoids polluting the shared messaging contract with transport-only lineage

### 4. observed-request normalization into `EventEnvelope`

The first live-path normalizer should extend the existing messaging policy normalizer rather than replacing it.

Recommended shape:

- keep `poc/messaging/policy.rs::normalize_classified_action(...)` as the provider-neutral baseline
- add one live-path helper that starts from the same normalized messaging event and then injects live lineage from `ObservedMessagingAction`

The resulting event must preserve all existing messaging attributes plus these live fields:

- `request_id`
- `correlation_id`
- `observation_provenance="observed_request"`
- `live_request_source_kind`
- `session_correlation_status`
- `session_correlation_reason`
- `validation_status` absent for this first path
- `validation_capture_source` absent for this first path

This is the minimum needed so durable records and local inspection can say:

- this was not a fixture preview
- this did reach the real ingress seam
- this has not yet been promoted to validated observation

### 5. policy and approval projection

Reuse the existing messaging policy surface unchanged.

For the first Discord path, the policy input should still be the shared messaging action family:

- `action_family="message.send"`
- `provider_id="discord"`
- `action_key="channels.messages.create"`
- `semantic_surface="discord.channels"`
- `channel_hint="discord.channels/{channel_id}"`
- `target_hint="discord.channels/{channel_id}/messages"`
- `delivery_scope="public_channel"`
- `content_retained=false`

The important rule is that live provenance enriches the normalized event, but it does **not** bypass the checked-in messaging policy boundary.

### 6. durable record reflection

Reuse the existing record reflection and durable append path:

- `poc/messaging/record.rs`
- `poc/messaging/persist.rs`
- shared durable persistence from P19-5 through P19-7

The resulting durable audit record must therefore carry both:

1. the messaging governance attributes
2. the durable record metadata already expected by the remote audit path

Minimum durable evidence expectations for the first path:

- append-only audit record in the remote durable store
- `observation_provenance="observed_request"`
- no `validation_status` yet
- durable integrity metadata
- durable storage lineage metadata

## minimum normalized field set

For the first Hermes/Discord durable path, reviewers should expect the normalized event and durable audit record to preserve at least these fields:

### live lineage

- `request_id`
- `correlation_id`
- `session_id`
- `agent_id`
- optional `workspace_id`
- `observation_provenance`
- `live_request_source_kind`
- `session_correlation_status`
- `session_correlation_reason`

### Discord/provider lineage

- `provider_id`
- `action_key`
- `provider_action_id`
- `semantic_surface`
- `semantic_action_label`
- `method`
- `host`
- `path_template`
- `query_class`

### messaging semantics

- `action_family`
- `target_hint`
- `channel_hint`
- `delivery_scope`
- `oauth_scope_labels`
- `side_effect`
- `privilege_class`
- `content_retained=false`

### durable evidence lineage

- `durable_integrity`
- `durable_storage_lineage`

## what should stay out of the first path

The first path must continue to exclude:

- raw Discord message content
- embeds/components payloads
- attachment bytes
- full guild/channel membership rosters
- opaque Discord token material
- provider-specific request-body blobs

If a later implementation needs one of those, it should first update the redaction boundary explicitly instead of smuggling content through normalization.

## relationship to later tasks

This design intentionally narrows the follow-on work:

- **P19-9** should implement the first real Discord semantic conversions against this path, then widen to additional routes such as edit/react/typing
- **P19-10** should make sure the observed Discord path preserves session / agent / workspace identity end to end
- **P19-11** should add the integration test that proves one Hermes/Discord request reaches durable audit through this exact path
- **P19-12** should decide when a Discord path may upgrade from `observed_request` to `validated_observation`

In other words, P19-8 fixes the shape of the first path; later tasks prove and widen it.

## review questions for follow-on implementation PRs

Before merging a follow-on Hermes/Discord implementation PR, reviewers should be able to answer:

1. does the live path still begin from the existing remote ingress + session-correlation contract?
2. is the first durable route still clearly `channels.messages.create`, or is the PR widening scope without saying so?
3. are live lineage fields injected in a live wrapper/boundary layer rather than leaking into the shared messaging contract gratuitously?
4. does the durable record preserve `observed_request` provenance without falsely claiming `validated_observation`?
5. do local inspection outputs show both messaging lineage and durable integrity/storage lineage without exposing raw Discord content?

If those answers are unclear, the implementation is probably mixing live-ingress ownership, messaging ownership, and durable-audit ownership too loosely.

## related docs

- messaging / collaboration governance boundary: [`messaging-collaboration-governance-foundation.md`](messaging-collaboration-governance-foundation.md)
- provider live preview adapters: [`provider-live-preview-adapter-boundaries.md`](provider-live-preview-adapter-boundaries.md)
- observed-runtime remote ingress contract: [`observed-runtime-remote-ingress-contract.md`](observed-runtime-remote-ingress-contract.md)
- real-traffic observation boundary: [`real-traffic-observation-boundary.md`](real-traffic-observation-boundary.md)
- remote audit tamper-evident strategy: [`remote-audit-tamper-evident-strategy.md`](remote-audit-tamper-evident-strategy.md)
- live preview record reflection: [`live-preview-record-reflection.md`](live-preview-record-reflection.md)
