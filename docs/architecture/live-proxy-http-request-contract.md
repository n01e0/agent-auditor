# live proxy HTTP request contract

This note fixes the first concrete redaction-safe request model that may cross the live proxy seam.

## Goal of P13-2

Define one small repository-owned request contract that a forward proxy, browser relay, or sidecar proxy can hand to hostd before session correlation and semantic conversion begin.

The contract is intentionally small:

- it is **HTTP-request shaped**, not provider-taxonomy shaped
- it carries **redaction-safe classes and hints**, not raw header values or bodies
- it is stable enough for session correlation, semantic conversion, policy, approval, and audit work to reuse without redefining the proxy seam each time

## Checked-in Rust model

`cmd/agent-auditor-hostd/src/poc/live_proxy/contract.rs` now fixes `LiveHttpRequestContract` with these fields:

- `source`
  - one of `forward_proxy`, `browser_relay`, `sidecar_proxy`
- `request_id`
  - stable proxy-owned request identity for one observed request
- `correlation_id`
  - cross-stage correlation label that later session / audit / approval work may reuse
- `transport`
  - stable lower-case transport label such as `http`, `https`, or `h2`
- `method`
  - one of the checked-in HTTP verbs: `GET`, `POST`, `PUT`, `PATCH`, `DELETE`, `HEAD`, `OPTIONS`
- `authority`
  - authority only; no scheme, path, query, fragment, or whitespace
- `path`
  - path component only; must begin with `/` and must not carry query / fragment data
- `headers`
  - a deduplicated set of redaction-safe header classes rather than raw header maps
- `body_class`
  - one checked-in class for the request body shape
- `auth_hint`
  - one checked-in authentication class rather than a token value
- `mode`
  - one of `shadow`, `enforce_preview`, `unsupported`

The field order is also fixed in code via `LIVE_HTTP_REQUEST_FIELDS` so the proxy seam plan and later live phases can share one exact minimal contract vocabulary.

## Redaction rules fixed by this contract

The request contract may carry:

- HTTP method
- authority label
- path
- request / correlation ids
- header classes
- body class
- auth hint
- proxy source
- mode label

The request contract may **not** carry:

- raw header values
- cookies
- bearer tokens
- request bodies
- response bodies
- query strings
- fragments
- message text
- file bytes
- provider-opaque payloads

In other words: the contract keeps routing and semantic clues, but not content.

## Fixed class vocabularies

### Header classes

The checked-in `LiveHttpHeaderClass` vocabulary is intentionally small and redaction-safe:

- `authorization`
- `browser_fetch`
- `conditional`
- `content_json`
- `content_form`
- `cookie`
- `file_upload_metadata`
- `idempotency_key`
- `message_metadata`
- `tenant_scope`

These are **classes**, not raw header names or values. The contract tells downstream code what kind of header signal was present, not what the exact secret or user content was.

### Body classes

The checked-in `LiveHttpBodyClass` vocabulary is:

- `none`
- `json`
- `form_urlencoded`
- `multipart_form_data`
- `text`
- `binary`
- `unknown`

### Auth hints

The checked-in `LiveHttpAuthHint` vocabulary is:

- `none`
- `bearer`
- `basic`
- `cookie_session`
- `oauth_user`
- `oauth_service_account`
- `api_key`
- `unknown`

### Mode labels

The checked-in `LiveInterceptionMode` vocabulary is:

- `shadow`
- `enforce_preview`
- `unsupported`

## Validation rules

The contract fixes a few important validation rules in code:

- `request_id` and `correlation_id` must be non-blank and whitespace-free
- `transport` must be a non-blank lower-case label without URI punctuation
- `authority` must not include scheme / path / query / fragment data
- `path` must start with `/` and must not include scheme / query / fragment data
- `headers` are deduplicated into a deterministic order before handoff

These validations matter because they prevent the proxy seam from silently smuggling larger URI shapes or unstable header blobs into later stages.

## Preview fixture

The checked-in preview request is a GitHub repository visibility update shape:

- `source=forward_proxy`
- `request_id=req_live_proxy_github_repos_update_visibility_preview`
- `correlation_id=corr_live_proxy_github_repos_update_visibility_preview`
- `transport=https`
- `method=PATCH`
- `authority=api.github.com`
- `path=/repos/n01e0/agent-auditor`
- `headers=[authorization, content_json]`
- `body_class=json`
- `auth_hint=bearer`
- `mode=shadow`

That preview is intentionally generic enough to validate the request contract itself without yet deciding session ownership or GitHub-specific taxonomy.

## What this contract deliberately does not do

This task does **not** define:

- session ownership
- provider-specific taxonomy
- a generic live action envelope in `agenta-core`
- policy decisions
- approval wait-state
- audit record shape
- proxy deployment or certificate handling

Those belong to the later live-proxy tasks.

## Relationship to neighboring docs

- phase boundary and responsibility split: [`live-proxy-interception-foundation.md`](live-proxy-interception-foundation.md)
- shared `agenta-core` live envelope above this request model: [`generic-live-action-envelope.md`](generic-live-action-envelope.md)
- overall architecture position: [`overview.md`](overview.md)
- Rust module split: [`rust-implementation.md`](rust-implementation.md)
