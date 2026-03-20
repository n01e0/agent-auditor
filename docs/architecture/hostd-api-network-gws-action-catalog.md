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

## Out of scope for this note

- proving at runtime which OAuth scope a token actually carried
- handling every alternative Google scope combination in policy
- deciding approval policy outcomes for these actions
- expanding beyond the first four GWS semantic actions
