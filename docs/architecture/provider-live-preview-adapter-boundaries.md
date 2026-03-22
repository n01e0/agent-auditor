# provider live preview adapter boundaries

This note fixes the first checked-in provider-specific live preview adapter boundaries that consume the shared live proxy envelope and hand off provider semantic actions.

## Goal of P13-6

Add concrete preview-scoped adapter boundaries for:

- Google Workspace (GWS)
- GitHub
- messaging providers (Slack and Discord)

Each adapter starts from the same shared `GenericLiveActionEnvelope` and stops at the provider semantic-action boundary used by the existing provider-specific governance slices.

## Shared upstream contract

All three adapters consume the same shared redaction-safe input from `agenta-core`:

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

The adapters do **not** reopen raw headers, raw bodies, cookies, bearer tokens, query strings, message text, or file bytes.

## Checked-in Rust modules

The new live adapter modules live in `cmd/agent-auditor-hostd/src/poc/live_proxy/`:

- `gws.rs`
- `github.rs`
- `messaging.rs`

Each module:

- consumes `GenericLiveActionEnvelope`
- performs preview-scoped route and target matching
- hands off provider semantic actions using existing provider-specific governance types
- includes checked-in preview fixtures and unit coverage

## GWS live preview adapter

`gws.rs` defines `GwsLivePreviewAdapterPlan`.

The GWS adapter currently classifies four preview actions:

- `drive.permissions.update`
- `drive.files.get_media`
- `gmail.users.messages.send`
- `admin.reports.activities.list`

### Important GWS constraint

The shared live proxy contract intentionally strips query strings. That means the old API/network classifier signal `?alt=media` is not available on the live proxy path.

The new GWS live preview adapter therefore uses a redaction-safe `target_hint` to keep `drive.files.get_media` distinguishable from a plain Drive file metadata read.

In other words: the adapter proves the boundary, but it also makes the missing-query constraint explicit.

## GitHub live preview adapter

`github.rs` defines `GitHubLivePreviewAdapterPlan`.

The GitHub adapter reuses the existing GitHub taxonomy plan by first projecting the live envelope into a redaction-safe `GitHubGovernanceObservation`.

It currently classifies all six checked-in GitHub preview actions:

- `repos.update_visibility`
- `branches.update_protection`
- `actions.workflow_dispatch`
- `actions.runs.rerun`
- `pulls.merge`
- `actions.secrets.create_or_update`

### Important GitHub constraint

Some GitHub actions need the adapter to preserve or project `target_hint` explicitly even when the route alone is not enough. The clearest example is `repos.update_visibility`, where `PATCH /repos/{owner}/{repo}` is not specific enough without a visibility target hint.

## Messaging live preview adapter

`messaging.rs` defines `MessagingLivePreviewAdapterPlan`.

The messaging adapter maps live proxy previews into provider-scoped candidates and then reuses the shared messaging taxonomy boundary.

It currently classifies six checked-in provider actions:

- Slack `chat.post_message`
- Slack `conversations.invite`
- Slack `files.upload_v2`
- Discord `channels.messages.create`
- Discord `channels.thread_members.put`
- Discord `channels.permissions.put`

### Important messaging constraint

Slack message, invite, and file-upload endpoints carry their channel/member/file targeting information in request bodies, which the live proxy contract intentionally does not retain.

The live preview adapter therefore requires a redaction-safe `target_hint` for those Slack routes. That keeps the seam honest: the adapter can classify the preview only if upstream semantic conversion already projected the safe target identity.

## What the new tests prove

The new tests prove that:

- each provider adapter consumes `GenericLiveActionEnvelope::field_names()` directly
- GWS preview routes can become checked-in `ClassifiedGwsAction` values
- GitHub preview routes can become checked-in `ClassifiedGitHubGovernanceAction` values
- Slack/Discord preview routes can become checked-in `ClassifiedMessagingAction` values
- unsupported routes or missing provider / target hints fail explicitly rather than silently guessing

## What this task still does not claim

These adapters are still **preview-only**.

This task does **not** prove:

- live policy enforcement is fail-closed
- approval holds can pause in-flight provider requests
- audit reflection is attached to these provider live paths yet
- all provider routes are covered
- target hints are available for every real provider flow

The task proves the provider-specific semantic adapter boundaries only.

## Related docs

- live proxy phase boundary: [`live-proxy-interception-foundation.md`](live-proxy-interception-foundation.md)
- live proxy request contract: [`live-proxy-http-request-contract.md`](live-proxy-http-request-contract.md)
- shared live envelope: [`generic-live-action-envelope.md`](generic-live-action-envelope.md)
- generic REST live preview adapter: [`generic-rest-live-preview-path.md`](generic-rest-live-preview-path.md)
- live coverage posture: [`live-proxy-coverage-matrix.md`](live-proxy-coverage-matrix.md)
