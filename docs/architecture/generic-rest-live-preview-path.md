# generic REST live preview path

This note fixes the first checked-in live preview path from the proxy seam into the existing generic REST contract.

## Goal of P13-5

Implement one concrete live preview adapter that starts from the shared proxy-owned live envelope and ends at the already-checked-in generic REST event shape that `agenta-policy` can evaluate.

This task is intentionally narrower than full provider-specific live interception:

- it proves a **generic REST** live preview path
- it uses a **small checked-in preview route set**
- it does **not** claim full provider taxonomy coverage
- it does **not** yet connect audit / approval persistence or inline enforcement outcomes

Those remain later live-proxy tasks.

## Checked-in Rust path

`cmd/agent-auditor-hostd/src/poc/live_proxy/generic_rest.rs` now defines `GenericRestLivePreviewPlan`.

That plan:

- consumes `GenericLiveActionEnvelope`
- matches a tiny preview route catalog
- joins docs-backed provider metadata
- normalizes the result into the existing generic REST event / action contract

The checked-in stage sequence is:

- `match_preview_route`
- `join_provider_metadata`
- `normalize_generic_rest_event`

## Shared upstream contract it consumes

The adapter consumes the same shared `agenta-core` live envelope introduced earlier:

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

The adapter does **not** reopen raw request bodies, raw header values, cookies, or tokens. It only consumes the redaction-safe live envelope.

## Generic REST contract it produces

The adapter normalizes the live envelope into the existing generic REST action contract fields:

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

Those fields are written onto a normal `EventEnvelope` action so the existing `PolicyInput::from_event(...)` generic REST logic can read them without a second live-only policy shape.

## Checked-in preview route set

The adapter is intentionally small. It recognizes exactly the three preview routes already used by the repository’s generic REST preview policy examples:

| Preview route | Derived generic REST action | Expected policy outcome |
|---|---|---|
| `GET admin.googleapis.com /admin/reports/v1/activity/users/all/applications/{applicationName}` | `gws:admin.reports.activities.list` | `allow` |
| `POST gmail.googleapis.com /gmail/v1/users/{userId}/messages/send` | `gws:gmail.users.messages.send` | `require_approval` |
| `PUT api.github.com /repos/{owner}/{repo}/actions/secrets/{secret_name}` | `github:actions.secrets.create_or_update` | `deny` |

This is a **preview catalog**, not a claim that generic REST now understands all GWS or GitHub routes.

## What the adapter joins

The live preview adapter joins docs-backed provider metadata for those preview routes only:

- OAuth scope labels
- side-effect description
- privilege class
- canonical route template / query classification

That metadata is what makes the resulting event compatible with the existing generic REST policy surface.

## What the tests now prove

The checked-in tests prove that:

- the live preview adapter consumes `GenericLiveActionEnvelope::field_names()` directly
- the allow preview normalizes into a generic REST event for `admin.reports.activities.list`
- the hold preview normalizes into a generic REST event for `gmail.users.messages.send`
- the deny preview normalizes into a generic REST event for `actions.secrets.create_or_update`
- the resulting events feed the existing generic REST Rego example and hit the expected `allow` / `require_approval` / `deny` outcomes
- missing `provider_hint` or an unmapped route fails explicitly instead of silently guessing

That is enough to prove the live proxy seam can already reach the generic REST policy surface in preview form.

## What this task deliberately does not do

This task does **not** yet add:

- broad provider-specific live route catalogs
- GWS / GitHub / messaging live semantic adapter boundaries
- approval-request persistence from the live path
- live audit reflection
- mode-specific realized enforcement status
- inline fail-closed interception

Those remain in the later P13 tasks.

## Relationship to neighboring docs

- live proxy phase boundary: [`live-proxy-interception-foundation.md`](live-proxy-interception-foundation.md)
- live proxy request contract: [`live-proxy-http-request-contract.md`](live-proxy-http-request-contract.md)
- shared live envelope: [`generic-live-action-envelope.md`](generic-live-action-envelope.md)
- generic REST governance boundary: [`generic-rest-oauth-governance-foundation.md`](generic-rest-oauth-governance-foundation.md)
- live coverage posture: [`live-proxy-coverage-matrix.md`](live-proxy-coverage-matrix.md)
