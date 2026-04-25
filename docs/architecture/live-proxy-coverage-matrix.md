# live proxy semantic coverage matrix

This note fixes the current coverage matrix for the planned live proxy path from the shared proxy seam into generic REST, GWS, GitHub, and messaging semantic layers.

Unless stated otherwise, this matrix still describes the repository's fixture-preview / preview-policy posture rather than a blanket validated real-traffic claim. The evidence boundary between fixture preview, observed request, and validated observation is fixed separately in [`real-traffic-observation-boundary.md`](real-traffic-observation-boundary.md).

As of the current revision, the repository-wide live-traffic story is intentionally uneven:

- the shared forward-proxy runtime path now exposes an **observed-request** tier for redaction-safe ingress metadata
- the GitHub slice additionally has **one validated observation** for `repos.update_visibility`
- the rest of the checked-in slice coverage remains fixture-preview only unless this matrix says otherwise

Read each row as the strongest claim that row can honestly support, not as a blanket upgrade for every downstream slice.

## Goal of P13-4

Document what is currently true for each downstream slice once the live proxy seam exists:

- which shared live input reaches the slice
- how session ownership is expected to be established
- which semantic-action sample is currently checked in
- what constraints still block a production live claim
- whether the slice is fail-open or may claim fail-closed
- whether approval hold is only modeled in preview records or is actually feasible inline

The matrix is intentionally conservative. A checked-in contract, taxonomy, policy rule, approval request, or audit record does **not** by itself prove that a live request can be paused or blocked before completion.

## Shared live path fixed before slice-specific adapters

The live proxy work now fixes two shared upstream contracts:

1. [`live-proxy-http-request-contract.md`](live-proxy-http-request-contract.md)
   - redaction-safe request facts captured at the proxy seam
2. [`generic-live-action-envelope.md`](generic-live-action-envelope.md)
   - shared `agenta-core` envelope after session correlation and before provider-specific taxonomy

Every row below assumes the same upstream live ownership rule:

- the **proxy seam** captures redaction-safe request metadata only
- the **session correlation** stage owns `session_id`, `agent_id`, `workspace_id`, and `correlation_status`
- downstream generic REST / GWS / GitHub / messaging slices should **consume** that ownership, not re-decide raw proxy capture

## End-to-end slice matrix

| Slice | Live proxy input consumed from the shared seam | Checked-in semantic sample today | Highest evidence tier currently checked in | Session correlation method for the live path | Current constraints that still block a production live claim | Failure posture for live execution today | Approval hold feasibility today | Adapter status |
|---|---|---|---|---|---|---|---|---|
| generic REST | `GenericLiveActionEnvelope` with shared lineage plus `method`, `authority`, `path`, `headers`, `body_class`, `auth_hint`, `provider_hint`, `target_hint`, and `mode` | Checked-in live preview route catalog for GWS admin activity listing, GWS Gmail send, and GitHub Actions secret create/update | **Fixture preview at the slice surface.** The shared forward-proxy seam is real upstream work, but the generic REST slice does not yet publish its own observed-request or validated-observation inspection contract. | Reuse the shared live proxy session-correlation stage (`request_id` / `correlation_id` / runtime lineage -> `session_id`). The generic REST layer preserves that lineage rather than introducing a second linker. | A live generic REST preview adapter now exists, but it only covers a tiny checked-in preview route catalog; it still depends on docs-backed metadata joins; auth labels are docs-backed, not runtime-verified; provider-specific live adapter families remain separate follow-on work. | **Fail-open**. The repository can now normalize and evaluate the checked-in generic REST live preview routes, but no live generic REST request can yet be paused or blocked inline. | **Preview-only** for approval-gated actions. Generic REST live preview can now reach existing policy outcomes, but no live hold / resume path exists yet. | **Implemented in P13-5** for the three checked-in preview routes. |
| GWS | The shared live envelope plus GWS routing hints (`provider_hint=gws` or GWS `authority` / `path` / target clues) feeding the existing GWS semantic-action slice | Four checked-in semantic actions: `drive.permissions.update`, `drive.files.get_media`, `gmail.users.messages.send`, `admin.reports.activities.list` | **Observed request** for the forward-proxy Gmail-send runtime path (`forward_proxy_*` bootstrap/test output). The broader GWS slice is still mostly fixture preview, and no GWS action is a validated observation yet. | For the live proxy path, use the shared proxy session-correlation stage and carry its `session_id` downstream. The older GWS `session_linkage` stage still matters for non-proxy API/network observers, but a proxy-correlated live request should not need a second ownership pass. | A live GWS semantic adapter now exists, but it is still preview-scoped; `drive.files.get_media` depends on an explicit redaction-safe `target_hint` because the shared proxy contract intentionally strips query strings such as `alt=media`; OAuth scope handling is docs-fixed, not runtime-verified. | **Fail-open** for live execution. `drive.permissions.update`, `drive.files.get_media`, and `gmail.users.messages.send` are documented as `approval_hold_preview`; `admin.reports.activities.list` is `observe_only_allow_preview`. None are a validated fail-closed subset yet. | **Preview-only** for the three approval-gated actions above. Hold metadata and pending approval requests are proven, but there is no live in-flight hold or resume path. | **Implemented in P13-6** for the four checked-in preview routes. |
| GitHub | The shared live envelope plus GitHub routing hints (`provider_hint=github`, GitHub `authority` / `path`, and redaction-safe `target_hint`) feeding the existing GitHub semantic-governance slice | Six checked-in semantic actions: `repos.update_visibility`, `branches.update_protection`, `actions.workflow_dispatch`, `actions.runs.rerun`, `pulls.merge`, `actions.secrets.create_or_update` | **Validated observation** for `repos.update_visibility` through `forward_proxy_observed_runtime_path`. The other five checked-in GitHub actions still remain fixture preview at the slice surface. | GitHub already assumes upstream session attribution before taxonomy begins. The live proxy path now satisfies that assumption for the checked-in observed runtime path by handing the GitHub slice a correlated live envelope with `session_id`, `agent_id`, and `workspace_id` already attached. | A live GitHub semantic adapter now exists, but it is still preview-scoped outside the one validated path; classification still depends on redaction-safe route hints and, for cases like `repos.update_visibility`, an explicit `target_hint`; permission labels are docs-backed, not runtime-verified. | **Fail-open** for all live execution. `repos.update_visibility`, `branches.update_protection`, `actions.workflow_dispatch`, and `pulls.merge` have reflected hold metadata only; `actions.secrets.create_or_update` has reflected deny metadata only; `actions.runs.rerun` is observe/allow only. Even the validated observation is not a validated fail-closed subset. | **Preview-only** for the four approval-gated actions above. Approval records can be created, but there is no live GitHub pause / review / resume mechanism yet. | **Implemented in P13-6** for the six checked-in preview routes, with one validated-observation path now exposed for `repos.update_visibility`. |
| messaging | The shared live envelope first feeds upstream provider taxonomy and generic REST lineage, then the messaging family layer derives collaboration semantics such as `message.send` or `channel.invite` | Six checked-in provider actions spanning four shared families: `message.send`, `channel.invite`, `permission.update`, `file.upload` across Slack and Discord preview samples | **Validated observation** for Discord `channels.messages.create` through `forward_proxy_observed_runtime_path`. The other checked-in messaging actions still remain preview-scoped at the slice surface. | Reuse the shared live proxy session-correlation stage, then preserve that lineage through provider taxonomy and generic REST lineage into the messaging family layer. The messaging slice should not add a separate live-session linker of its own. | A live messaging semantic adapter now exists, but only one Discord message-send route is validated today; Slack routes still depend on explicit redaction-safe `target_hint` values because the proxy contract intentionally omits message / invite / file-upload bodies; permissions/scopes are docs-backed, not runtime-verified. | **Fail-open** for live execution. Discord `channels.messages.create` now has validated-observation evidence for the audited path, but it is still not a validated fail-closed subset; membership expansion and file upload remain approval-hold preview, and permission overwrite update remains deny preview only. | **Preview-only** for `channel.invite` and `file.upload`. Approval records can be created, but there is still no inline live messaging hold/resume path. | **Implemented in P13-6** for the six checked-in provider preview routes, with one Hermes/Discord validated-observation path now exposed for `channels.messages.create`. |

## What each row means in practice

### generic REST

The generic REST layer is the earliest downstream consumer of the shared live envelope, but it is still not a standalone traffic classifier.

- It now consumes the shared live envelope after proxy correlation through the checked-in adapter in [`generic-rest-live-preview-path.md`](generic-rest-live-preview-path.md).
- It still depends on a tiny checked-in preview route catalog plus docs-backed metadata for `provider_id`, `action_key`, `target_hint`, and auth/risk descriptors.
- The new adapter proves that live proxy input can reach the existing generic REST policy surface, but it does **not** yet claim broad route coverage or inline gating.

### GWS

The live proxy path and the older API/network GWS path must not be conflated.

- The existing GWS PoC already has its own `session_linkage -> classify -> evaluate -> record` split for API/network observers.
- For the live proxy path, the shared proxy session-correlation stage should satisfy the ownership requirement before the GWS semantic adapter runs.
- The checked-in GWS live preview adapter also makes one important seam limitation explicit: because query strings are stripped at the proxy contract, `drive.files.get_media` currently depends on a redaction-safe `target_hint` rather than a raw `?alt=media` hint.

### GitHub

The GitHub slice is already documented as requiring upstream attribution.

- The live proxy work gives GitHub a clear upstream ownership source: the correlated live envelope.
- The checked-in GitHub live preview adapter projects that envelope into `GitHubGovernanceObservation` and reuses the existing taxonomy plan.
- Visibility updates remain a good example of why `target_hint` matters: `PATCH /repos/{owner}/{repo}` alone is not specific enough.

### messaging

The messaging row is the most layered one.

- A live messaging path still has to flow through shared live correlation, provider taxonomy, and generic REST lineage before collaboration-family policy makes sense.
- The checked-in messaging live preview adapter now proves that Slack and Discord provider actions can be derived from the shared live envelope, but Slack still needs explicit `target_hint` projection because body content is intentionally absent.
- The shared live seam should stop at safe request and lineage facts; it should not smuggle raw message bodies or file content into the messaging layer.

## Checked-in semantic sample and current preview policy outcomes

### generic REST preview sample

| Checked-in preview action | Current preview policy outcome | Live interpretation today |
|---|---|---|
| GWS admin activity listing | `allow` | observe / allow preview only |
| GWS Gmail send | `require_approval` | preview-only approval candidate; live request would still fail open |
| GitHub Actions secret create/update | `deny` | preview-only deny reflection; live request would still fail open |

### GWS preview sample

| Checked-in semantic action | Current preview policy outcome | Live interpretation today |
|---|---|---|
| `drive.permissions.update` | `require_approval` | approval-hold preview only; fail open live |
| `drive.files.get_media` | `require_approval` | approval-hold preview only; fail open live |
| `gmail.users.messages.send` | `require_approval` | approval-hold preview only; fail open live |
| `admin.reports.activities.list` | `allow` | observe / allow preview only |

### GitHub preview sample

| Checked-in semantic action | Current preview policy outcome | Live interpretation today |
|---|---|---|
| `repos.update_visibility` | `require_approval` | approval-hold preview only; fail open live |
| `branches.update_protection` | `require_approval` | approval-hold preview only; fail open live |
| `actions.workflow_dispatch` | `require_approval` | approval-hold preview only; fail open live |
| `pulls.merge` | `require_approval` | approval-hold preview only; fail open live |
| `actions.secrets.create_or_update` | `deny` | deny preview only; fail open live |
| `actions.runs.rerun` | `allow` | observe / allow preview only |

### messaging preview sample

| Checked-in provider action / family | Current preview policy outcome | Live interpretation today |
|---|---|---|
| Slack `chat.post_message` / `message.send` | `allow` | observe / allow preview only |
| Discord `channels.messages.create` / `message.send` | `allow` | one validated-observation allow path through `forward_proxy_observed_runtime_path`; still fail open live |
| Slack `conversations.invite` / `channel.invite` | `require_approval` | approval-hold preview only; fail open live |
| Discord `channels.thread_members.put` / `channel.invite` | `require_approval` | approval-hold preview only; fail open live |
| Slack `files.upload_v2` / `file.upload` | `require_approval` | approval-hold preview only; fail open live |
| Discord `channels.permissions.put` / `permission.update` | `deny` | deny preview only; fail open live |

## Mode interpretation

The current repository now fixes three distinct live preview mode behaviors:

- `shadow`
  - `coverage_posture=observe_only_preview`
  - records policy signals without creating approval queue state
- `enforce_preview`
  - `coverage_posture=record_only_preview`
  - can create preview-only approval records for `require_approval`
- `unsupported`
  - `coverage_posture=unsupported_preview`
  - records diagnostic signals and coverage gaps without claiming a supported live preview contract

Those mode semantics are documented in [`live-preview-mode-semantics.md`](live-preview-mode-semantics.md), the operator-facing coverage / fail-open / unsupported visibility is documented in [`live-preview-coverage-visibility.md`](live-preview-coverage-visibility.md), and the append-only records are described in [`live-preview-record-reflection.md`](live-preview-record-reflection.md).

## Approval-hold interpretation

Across all four rows, the current repository now proves this narrower statement:

- the policy layer can mark an action `allow`, `deny`, or `require_approval`
- live preview records can reflect the realized runtime posture as `observe_only_fallback`
- a pending `ApprovalRequest` can be recorded locally for preview approval candidates

It does **not** yet prove:

- a real in-flight provider request can be paused before completion
- the pause can survive transport retries or provider timeouts
- a reviewer can approve and resume the original live request
- a deny or hold failure is fail-closed on the live request path

Until those conditions are validated for a specific action family, the live posture remains **fail-open with explicit preview metadata**, not fail-closed.

That distinction is now reflected directly in live preview records through:

- `failure_posture`
- `coverage_support`
- `coverage_summary`
- `coverage_gap`

## Operator summary

If someone asks "what does the live proxy path actually cover today?", the honest answer is:

- the repository now fixes the **shared live contracts** and the **per-slice semantic expectations**
- it proves checked-in **generic REST** and **provider-specific semantic** live preview adapters plus **preview policy / approval / audit shapes** for generic REST, GWS, GitHub, and messaging slices
- it proves an **observed request** tier for the hostd-owned forward-proxy runtime ingress path, with the checked-in example currently surfacing as a Gmail send / `gws_action` record
- it proves **validated observation** for GitHub `repos.update_visibility` and Hermes/Discord `channels.messages.create` through `capture -> correlate -> classify -> policy -> audit`, with durable `observation_provenance` / `validation_status` inspection output
- it does **not yet** prove broad validated-observation coverage across generic REST, GWS, GitHub, and messaging slices
- it does **not yet** prove an end-to-end live proxy adapter that can safely hold or deny traffic inline for any of those slices

That is exactly why the next task now focuses on final live-mode semantics (`P13-8`) rather than broader coverage claims.

## Related docs

- general architecture coverage matrix: [`coverage-matrix.md`](coverage-matrix.md)
- live proxy phase boundary: [`live-proxy-interception-foundation.md`](live-proxy-interception-foundation.md)
- real-traffic evidence boundary: [`real-traffic-observation-boundary.md`](real-traffic-observation-boundary.md)
- live proxy request contract: [`live-proxy-http-request-contract.md`](live-proxy-http-request-contract.md)
- generic live action envelope: [`generic-live-action-envelope.md`](generic-live-action-envelope.md)
- generic REST live preview adapter: [`generic-rest-live-preview-path.md`](generic-rest-live-preview-path.md)
- provider semantic live preview adapters: [`provider-live-preview-adapter-boundaries.md`](provider-live-preview-adapter-boundaries.md)
- live preview mode semantics: [`live-preview-mode-semantics.md`](live-preview-mode-semantics.md)
- live preview coverage visibility: [`live-preview-coverage-visibility.md`](live-preview-coverage-visibility.md)
- live preview record reflection: [`live-preview-record-reflection.md`](live-preview-record-reflection.md)
- generic REST constraints: [`generic-rest-oauth-governance-known-constraints.md`](generic-rest-oauth-governance-known-constraints.md)
- GWS constraints: [`hostd-api-network-gws-known-constraints.md`](hostd-api-network-gws-known-constraints.md)
- GitHub constraints: [`hostd-github-semantic-governance-known-constraints.md`](hostd-github-semantic-governance-known-constraints.md)
- messaging constraints: [`messaging-collaboration-governance-known-constraints.md`](messaging-collaboration-governance-known-constraints.md)
- failure posture policy: [`failure-behavior.md`](failure-behavior.md)
