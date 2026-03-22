# generic live action envelope

This note fixes the first `agenta-core` envelope that sits between the live proxy seam and any provider-specific taxonomy.

## Goal of P13-3

Define one shared `agenta-core` input that carries only redaction-safe live interception facts from hostd's proxy / session-correlation path into later generic REST / GWS / GitHub / messaging live adapters.

The envelope is intentionally **pre-taxonomy**:

- it does **not** contain provider action keys
- it does **not** contain generic REST policy metadata
- it does **not** contain messaging action families
- it does **not** contain policy decisions, approval state, or audit records

It is the common input that later provider-specific taxonomy will read.

## Checked-in Rust model

`crates/agenta-core/src/live.rs` now defines `GenericLiveActionEnvelope` with these fields:

- `source`
- `request_id`
- `correlation_id`
- `session_id`
- `agent_id`
- `workspace_id`
- `provider_hint`
- `correlation_status`
- `live_surface`
- `transport`
- `method`
- `authority`
- `path`
- `headers`
- `body_class`
- `auth_hint`
- `target_hint`
- `mode`
- `content_retained`

The field order is fixed by `GENERIC_LIVE_ACTION_FIELDS` so hostd's live proxy semantic-conversion boundary and later adapters can share one exact vocabulary.

## What the envelope means

### Shared lineage and ownership

These fields tell downstream code which runtime request is being discussed without committing to provider taxonomy yet:

- `request_id`
- `correlation_id`
- `session_id`
- `agent_id`
- `workspace_id`
- `correlation_status`

### Shared transport and request shape

These fields describe the intercepted HTTP request in a redaction-safe way:

- `source`
- `live_surface`
- `transport`
- `method`
- `authority`
- `path`
- `headers`
- `body_class`
- `auth_hint`

### Shared routing hints for later taxonomy

These fields help later adapters decide which taxonomy or family to evaluate without embedding the final answer in the envelope itself:

- `provider_hint`
- `target_hint`
- `mode`
- `content_retained`

`content_retained` is fixed to `false` in the checked-in constructor and preview fixture. If a future live path needs content retention, that must be a new explicit boundary decision rather than an accidental expansion of this seam.

## Redaction rule

The checked-in `GENERIC_LIVE_ACTION_REDACTION_RULE` says the envelope may carry:

- proxy source
- request and correlation ids
- session lineage
- provider hints
- live surface hints
- method / authority / path labels
- header classes
- body classes
- auth hints
- target hints
- mode labels
- content-retention status

It may **not** carry:

- raw header values
- cookies
- bearer tokens
- request bodies
- response bodies
- message text
- file bytes
- provider-opaque payloads

## Shared `agenta-core` types reused here

The envelope deliberately reuses existing shared core types where that keeps contracts aligned:

- `ProviderId` for `provider_hint`
- `ProviderMethod` for `method`
- `RestHost` for `authority`

The remaining live-only pieces are defined in the new `live` module because they are specific to the proxy / interception seam:

- `LiveCaptureSource`
- `LiveRequestId`
- `LiveCorrelationId`
- `LiveTransport`
- `LiveSurface`
- `LivePath`
- `LiveCorrelationStatus`
- `LiveHeaderClass` / `LiveHeaders`
- `LiveBodyClass`
- `LiveAuthHint`
- `LiveInterceptionMode`

## Preview fixture

The checked-in preview envelope keeps the same GitHub visibility-change request used by the proxy contract slice, but now as shared `agenta-core` input:

- `source=forward_proxy`
- `request_id=req_live_proxy_github_repos_update_visibility_preview`
- `correlation_id=corr_live_proxy_github_repos_update_visibility_preview`
- `session_id=sess_live_proxy_preview`
- `agent_id=openclaw-main`
- `workspace_id=agent-auditor`
- `provider_hint=github`
- `correlation_status=confirmed`
- `live_surface=http.request`
- `transport=https`
- `method=PATCH`
- `authority=api.github.com`
- `path=/repos/n01e0/agent-auditor`
- `headers=[authorization, content_json]`
- `body_class=json`
- `auth_hint=bearer`
- `target_hint=repos/n01e0/agent-auditor/visibility`
- `mode=shadow`
- `content_retained=false`

That fixture is intentionally still pre-taxonomy: it hints that the request is probably GitHub-related, but it does not yet decide `pulls.merge`, `repos.update_visibility`, or any other provider-local action key.

## Hostd handoff fixed by this task

`cmd/agent-auditor-hostd/src/poc/live_proxy/semantic_conversion.rs` now points its semantic handoff fields at `GenericLiveActionEnvelope::field_names()` and exposes a checked-in preview conversion into `agenta-core`.

That means the semantic-conversion boundary is no longer just a text plan. It now has a concrete shared Rust shape for the live envelope that later provider-specific taxonomy can consume.

## What this task deliberately does not do

This task does **not** define:

- provider-local action taxonomy
- generic REST metadata joins
- GWS / GitHub / messaging family conversion
- policy evaluation
- approval hold semantics
- audit record shapes

Those remain in later live-proxy tasks.

## Relationship to neighboring docs

- phase boundary and ownership split: [`live-proxy-interception-foundation.md`](live-proxy-interception-foundation.md)
- proxy request contract beneath this envelope: [`live-proxy-http-request-contract.md`](live-proxy-http-request-contract.md)
- overall architecture position: [`overview.md`](overview.md)
- Rust module split: [`rust-implementation.md`](rust-implementation.md)
