# provider abstraction GitHub candidate catalog

This note fixes the first GitHub action candidates and the docs-backed metadata shape for the next provider slice after Google Workspace.

It is intentionally a **catalog-only** document. It does not claim that a GitHub classifier, interceptor, or policy runtime already exists.

Snapshot date for the external source links below: **2026-03-21**.

## Why this note exists

P8-2 through P8-5 already fixed the shared provider contract and metadata types:

- contract identity: `provider_id + action_key + target_hint`
- shared metadata fields: `method`, `canonical_resource`, `side_effect`, `oauth_scopes`, `privilege_class`
- policy input surface: `input.provider_action.provider_id` + `input.provider_action.action_key`

Before a GitHub provider implementation lands, the repository still needs one docs-backed answer to two questions:

1. which GitHub action keys should the next slice treat as the initial candidate set?
2. how should GitHub auth and metadata map onto the already-checked-in shared metadata shape?

This note fixes both so later implementation work can add code against a stable catalog instead of re-deciding names and field shapes mid-flight.

## Fixed metadata shape for GitHub candidates

Every GitHub catalog row below maps 1:1 onto `agenta_core::provider::ProviderActionMetadata`.

The fixed rules are:

- `action.provider_id` is always `github`
- `action.action_key` uses lowercase dotted keys with underscores only when the official action name needs them
- `method` stays the official HTTP verb from the GitHub REST endpoint
- `canonical_resource` is a redaction-safe resource template, never a raw issue body, PR body, file blob, diff, or review text
- `side_effect` describes the observable effect of the endpoint, not the request payload
- `privilege_class` stays on the shared enum values from `agenta-core`; we do **not** invent GitHub-only privilege labels for this layer

### Auth labels inside `oauth_scopes`

The checked-in shared field name is still `oauth_scopes`, but GitHub documentation mixes two auth vocabularies:

- fine-grained repository or organization permissions such as **Contents**, **Pull requests**, and **Administration**
- classic OAuth / PAT scopes such as `repo`, `read:org`, and `admin:org`

To keep the metadata JSON shape stable **without** pretending every GitHub auth label is literally an OAuth scope, this catalog fixes the following string forms inside `oauth_scopes`:

- `github.permission:<permission>:<access>` for fine-grained permission labels
- `github.oauth:<scope>` for classic OAuth / PAT scope labels

That gives later policy and audit code one stable auth-label field today, while still leaving room to split permissions vs scopes into separate types in a later phase if the repository ever needs that extra precision.

### JSON shape fixed for the next GitHub slice

```json
{
  "entries": [
    {
      "action": {
        "provider_id": "github",
        "action_key": "repos.contents.get"
      },
      "method": "get",
      "canonical_resource": "repos/{owner}/{repo}/contents/{path}",
      "side_effect": "returns repository file or directory metadata and may return file content bytes via raw/object media types",
      "oauth_scopes": {
        "primary": "github.permission:contents:read",
        "documented": [
          "github.permission:contents:read",
          "github.oauth:repo"
        ]
      },
      "privilege_class": "content_read"
    }
  ]
}
```

The table below fully instantiates that shape for the initial candidate action set.

## Fixed candidate action catalog

| Candidate action | Official method | Canonical resource | Observable side effect | Primary auth label | Documented auth labels | Privilege class |
| --- | --- | --- | --- | --- | --- | --- |
| `repos.contents.get` | `GET /repos/{owner}/{repo}/contents/{path}` | `repos/{owner}/{repo}/contents/{path}` | Returns repository file or directory metadata and, for file reads with GitHub's raw/object media types, can return file content bytes or download URLs. | `github.permission:contents:read` | `github.permission:contents:read`, `github.oauth:repo` | `content_read` |
| `repos.contents.create_or_update` | `PUT /repos/{owner}/{repo}/contents/{path}` | `repos/{owner}/{repo}/contents/{path}` | Creates a new file or updates an existing file by writing Base64-decoded content to the repository at the target path. | `github.permission:contents:write` | `github.permission:contents:write`, `github.oauth:repo` | `content_write` |
| `pulls.create` | `POST /repos/{owner}/{repo}/pulls` | `repos/{owner}/{repo}/pulls` | Opens a pull request from a head branch to a base branch; creates a reviewable collaboration artifact and can notify subscribers or requested reviewers. | `github.permission:pull_requests:write` | `github.permission:pull_requests:write`, `github.oauth:repo` | `content_write` |
| `repos.collaborators.add` | `PUT /repos/{owner}/{repo}/collaborators/{username}` | `repos/{owner}/{repo}/collaborators/{username}` | Adds a repository collaborator, invites an outside collaborator, or changes an existing collaborator's permission level; the endpoint explicitly triggers notifications. | `github.permission:administration:write` | `github.permission:administration:write`, `github.oauth:repo`, `github.oauth:read:org` | `sharing_write` |

## Why these four candidates

This initial GitHub slice is intentionally small, but it already exercises the shared cross-provider metadata model in a way that GWS alone could not prove:

- `repos.contents.get` fixes a **content-read** candidate that can expose repository bytes without introducing a Git blob or archive-specific contract yet
- `repos.contents.create_or_update` fixes a **content-write** candidate against a common, high-signal repository mutation path
- `pulls.create` fixes a **collaboration artifact creation** path that is not just file mutation, but still maps cleanly onto the shared metadata shape
- `repos.collaborators.add` fixes a **sharing / access broadening** path so the GitHub slice is not limited to content-only actions

Together these four candidates prove that the shared contract and metadata fields can carry GitHub repository reads, writes, review-surface creation, and access mutations without inventing a second provider-specific metadata schema.

## Deliberate non-goals for this catalog

This note intentionally does **not** fix every plausible GitHub action up front.

Still out of scope here:

- issue comments, review comments, and review submission sub-actions
- webhook, Actions, Checks, and package-registry actions
- org-level or enterprise-level audit-log slices
- GraphQL-specific action naming
- runtime proof that a live token actually carried the documented label in `oauth_scopes`
- live interception, fail-closed claims, or enforcement posture claims for GitHub traffic

The point of this note is smaller: the next GitHub provider phase should be able to start with a stable action key set and a stable metadata JSON shape.

## Official source URLs

### Repository contents

- REST API endpoints for repository contents: <https://docs.github.com/en/rest/repos/contents>
- Fine-grained PAT permissions reference: <https://docs.github.com/en/rest/authentication/permissions-required-for-fine-grained-personal-access-tokens>

### Pull requests

- REST API endpoints for pull requests: <https://docs.github.com/en/rest/pulls/pulls>
- Fine-grained PAT permissions reference: <https://docs.github.com/en/rest/authentication/permissions-required-for-fine-grained-personal-access-tokens>

### Collaborators

- REST API endpoints for collaborators: <https://docs.github.com/en/rest/collaborators/collaborators>
- Fine-grained PAT permissions reference: <https://docs.github.com/en/rest/authentication/permissions-required-for-fine-grained-personal-access-tokens>

## Related docs

- phase boundary: [`provider-abstraction-foundation.md`](provider-abstraction-foundation.md)
- architecture overview: [`overview.md`](overview.md)
- GWS action catalog: [`hostd-api-network-gws-action-catalog.md`](hostd-api-network-gws-action-catalog.md)
- shared provider contract and metadata types: [`../../crates/agenta-core/src/provider.rs`](../../crates/agenta-core/src/provider.rs)
- roadmap mirror: [`../roadmaps/provider-abstraction-foundation-tasklist.md`](../roadmaps/provider-abstraction-foundation-tasklist.md)
