# hostd API / network GWS semantic action catalog

This note fixes the first four Google Workspace semantic actions against Google’s official REST and auth documentation so later `evaluate` / policy work can depend on a stable meaning for each label.

Snapshot date for the source links below: **2026-03-20**.

## How to read this catalog

- **Official method** is the Google REST method that the current taxonomy maps onto.
- **Normalized resource** is the resource string the hostd semantic layer should talk about in docs and policy notes.
- **Observable side effect** is the user-visible or admin-visible effect called out by the official method docs.
- **Fixed policy scope** is the single OAuth scope this repository will use as the canonical documentation label for the action.
- **Method-doc scopes** records the broader scope set that Google says can authorize the method today.

For Drive methods, the official method docs often allow more than one scope. This catalog intentionally fixes one scope per semantic action so later policy docs and tests can talk about a stable label, while still preserving the full Google method-doc scope set in the last column.

## Fixed action contract

| Semantic action | Official method | Normalized resource | Observable side effect | Fixed policy scope | Method-doc scopes |
| --- | --- | --- | --- | --- | --- |
| `drive.permissions.update` | `PATCH https://www.googleapis.com/drive/v3/files/{fileId}/permissions/{permissionId}` | `drive.files/{fileId}/permissions/{permissionId}` | Updates a Drive permission with patch semantics; can also transfer ownership when `transferOwnership=true`, which explicitly acknowledges that side effect. | `https://www.googleapis.com/auth/drive.file` | `https://www.googleapis.com/auth/drive`, `https://www.googleapis.com/auth/drive.file` |
| `drive.files.get_media` | `GET https://www.googleapis.com/drive/v3/files/{fileId}?alt=media` | `drive.files/{fileId}/content` | Returns file content bytes instead of metadata; the docs explicitly say `alt=media` downloads content only for files stored in Drive. | `https://www.googleapis.com/auth/drive.readonly` | `https://www.googleapis.com/auth/drive`, `https://www.googleapis.com/auth/drive.appdata`, `https://www.googleapis.com/auth/drive.file`, `https://www.googleapis.com/auth/drive.meet.readonly`, `https://www.googleapis.com/auth/drive.metadata`, `https://www.googleapis.com/auth/drive.metadata.readonly`, `https://www.googleapis.com/auth/drive.photos.readonly`, `https://www.googleapis.com/auth/drive.readonly` |
| `gmail.users.messages.send` | `POST https://gmail.googleapis.com/gmail/v1/users/{userId}/messages/send` | `gmail.users/{userId}/messages:send` | Sends the specified message to the recipients in the `To`, `Cc`, and `Bcc` headers. | `https://www.googleapis.com/auth/gmail.send` | `https://mail.google.com/`, `https://www.googleapis.com/auth/gmail.modify`, `https://www.googleapis.com/auth/gmail.compose`, `https://www.googleapis.com/auth/gmail.send`, `https://www.googleapis.com/auth/gmail.addons.current.action.compose` |
| `admin.reports.activities.list` | `GET https://admin.googleapis.com/admin/reports/v1/activity/users/{userKey or all}/applications/{applicationName}` | `admin.reports/activity/users/{userKey-or-all}/applications/{applicationName}` | Retrieves audit activity rows for a customer and application; this is read-only audit retrieval, not a mutating action. | `https://www.googleapis.com/auth/admin.reports.audit.readonly` | `https://www.googleapis.com/auth/admin.reports.audit.readonly` |

## P7-2 enforcement priority and posture

The checked-in preview policy at `examples/policies/gws_action.rego` now has a matching machine-readable posture catalog at `cmd/agent-auditor-hostd/src/poc/gws/posture.rs`.

That catalog is intentionally small and only fixes the first four semantic actions so later GWS runtime work can depend on stable priority and posture labels without claiming that live interception already exists.

| Semantic action | Priority | Primary risk | Preview policy decision | Defined posture |
| --- | --- | --- | --- | --- |
| `drive.permissions.update` | `p0` | sharing mutation | `require_approval` | `approval_hold_preview` |
| `gmail.users.messages.send` | `p0` | outbound delivery | `require_approval` | `approval_hold_preview` |
| `drive.files.get_media` | `p1` | content exfiltration | `require_approval` | `approval_hold_preview` |
| `admin.reports.activities.list` | `p2` | audit read | `allow` | `observe_only_allow_preview` |

### Why this priority order

- `drive.permissions.update` stays at `p0` because changing Drive permissions can immediately broaden access and the official method also carries ownership-transfer semantics.
- `gmail.users.messages.send` stays at `p0` because it can deliver content outside the tenant and present as the user.
- `drive.files.get_media` stays at `p1` because it is a direct content-download path, but unlike the two `p0` actions it does not itself mutate sharing state or initiate an outbound send.
- `admin.reports.activities.list` stays at `p2` because it is read-only audit retrieval and therefore should remain visible in policy and audit records without being treated like a high-risk mutation or exfiltration primitive.

## P7-5 failure behavior and enforcement limitations

The current GWS path now reflects `require_approval` and synthetic `deny` outcomes into `agenta-core` event metadata plus local approval / audit records. That is useful for contract validation, but it still does **not** mean any live Google Workspace request can be stopped inline.

Until a real request adapter, browser relay, proxy, or egress-control seam can intercept the exact action before completion, every action below must still be documented as **fail-open for live execution**.

| Semantic action | Preview posture | Current reflected result in records | Honest runtime claim today | Failure behavior today | What is still missing before stricter claims are valid |
| --- | --- | --- | --- | --- | --- |
| `drive.permissions.update` | `approval_hold_preview` | `require_approval` can become a reflected `hold` outcome plus a pending approval record | high-risk sharing mutation is visible and can be modeled as “would hold” | **fail-open** for the real PATCH; no validated pre-request gate exists yet | a live adapter/proxy/browser seam that can pause the permission update before Google accepts it, maintain approval state, and either resume or cancel safely |
| `gmail.users.messages.send` | `approval_hold_preview` | `require_approval` can become a reflected `hold` outcome plus a pending approval record; synthetic `deny` can be reflected into audit metadata | outbound send risk is visible and the intended hold/deny decision can be recorded | **fail-open** for the real send; no validated send-blocking seam exists yet | a gate that can stop delivery before Gmail accepts the message, preserve hold state, and surface an operator decision without leaking the message |
| `drive.files.get_media` | `approval_hold_preview` | `require_approval` can become a reflected `hold` outcome plus a pending approval record | content-download risk is visible and can be modeled as “would hold” | **fail-open** for the real download; the current PoC cannot stop byte delivery inline | a request/response control point that can stop or defer the content response before file bytes are returned |
| `admin.reports.activities.list` | `observe_only_allow_preview` | current checked-in policy stays `allow`, so records stay observe/allow only | read-only audit retrieval remains visible for classification, policy, and audit | **fail-open / observe-only**; there is no deny/hold claim for this action in the checked-in posture | any future stricter claim would need a live intercept path first; until then even a future deny rule would still be documentation-only preview behavior |

### Practical reading rule

- `approval_hold_preview` means the docs and records may show the **intended** operator gate for that action.
- It does **not** mean the repository has earned a fail-closed or real pause claim for the live Google Workspace request.
- `observe_only_allow_preview` means the action is currently documented as visible-but-not-gated, even inside the preview contract.

## Why these fixed scopes

### `drive.permissions.update` → `drive.file`

Google’s Drive method doc for `permissions.update` allows either `drive` or `drive.file`. The Drive auth guide separately recommends using the most narrowly focused scope possible and explicitly recommends non-sensitive scopes for most use cases, with `drive.file` called out as the main per-file scope.

This repository therefore fixes `drive.file` as the canonical documentation scope for `drive.permissions.update`, while still recording that the broader `drive` scope also authorizes the method.

### `drive.files.get_media` → `drive.readonly`

The `files.get` method doc says that `alt=media` returns file contents, not just metadata. Among the official Drive scope descriptions, `drive.readonly` is the scope whose description directly names the capability to **view and download all Drive files**.

This repository therefore fixes `drive.readonly` as the canonical documentation scope for the generic content-download semantic action, while keeping the full method-doc scope list alongside it.

### `gmail.users.messages.send` → `gmail.send`

The Gmail method doc for `users.messages.send` allows several scopes, but the Gmail auth guide gives `gmail.send` the narrowest direct description for this action: **Send email on your behalf**.

This repository therefore fixes `gmail.send` as the canonical documentation scope for outbound Gmail send semantics.

### `admin.reports.activities.list` → `admin.reports.audit.readonly`

The Reports API method doc and the Reports auth guide line up cleanly here: the action is audit-log retrieval and the scope is `admin.reports.audit.readonly`.

## Official source URLs

### `drive.permissions.update`

- Method doc: <https://developers.google.com/workspace/drive/api/reference/rest/v3/permissions/update>
- Drive auth guide: <https://developers.google.com/workspace/drive/api/guides/api-specific-auth>

### `drive.files.get_media`

- Method doc (`files.get` with `alt=media`): <https://developers.google.com/workspace/drive/api/reference/rest/v3/files/get>
- Drive auth guide: <https://developers.google.com/workspace/drive/api/guides/api-specific-auth>

### `gmail.users.messages.send`

- Method doc: <https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages/send>
- Gmail auth guide: <https://developers.google.com/workspace/gmail/api/auth/scopes>

### `admin.reports.activities.list`

- Method doc: <https://developers.google.com/workspace/admin/reports/reference/rest/v1/activities/list>
- Reports auth guide: <https://developers.google.com/workspace/admin/reports/auth>

## Related docs

- phase boundary: [`hostd-api-network-gws-poc.md`](hostd-api-network-gws-poc.md)
- local runbook: [`../runbooks/hostd-api-network-gws-poc-local.md`](../runbooks/hostd-api-network-gws-poc-local.md)
- known constraints: [`hostd-api-network-gws-known-constraints.md`](hostd-api-network-gws-known-constraints.md)
- posture contract: [`../../cmd/agent-auditor-hostd/src/poc/gws/posture.rs`](../../cmd/agent-auditor-hostd/src/poc/gws/posture.rs)
- roadmap: [`../roadmaps/api-network-gws-semantic-action-layer-tasklist.md`](../roadmaps/api-network-gws-semantic-action-layer-tasklist.md)

## Out of scope for this note

- proving at runtime which OAuth scope a token actually carried
- handling every alternative Google scope combination in policy
- implementing live GWS hold / deny interception from the new posture catalog
- expanding beyond the first four GWS semantic actions
