# provider abstraction GitHub candidate catalog

This note fixes the docs-backed provider metadata for the first GitHub semantic-governance slice.

It is intentionally a **catalog-only** document. It does not claim that a live GitHub interceptor, normalized event path, policy runtime, or approval recorder already exists.

Snapshot date for the external source links below: **2026-03-21**.

## Why this note exists

P8 fixed the shared provider contract and metadata shape, and P9-1 / P9-2 fixed the GitHub semantic-governance boundary plus the first checked-in GitHub action taxonomy.

That still leaves one docs problem to solve before policy and record work lands:

1. which GitHub semantic action keys are fixed for the first governance slice?
2. what are the official method / canonical resource / required permission / side effect descriptors for each action?

This note fixes those answers from official GitHub docs so later metadata, policy, audit, and UI work can join against one stable catalog instead of re-deciding endpoint facts mid-flight.

## Fixed metadata shape for GitHub governance actions

Every row below maps 1:1 onto `agenta_core::provider::ProviderActionMetadata`.

The checked-in shared field names are still:

- `method`
- `canonical_resource`
- `side_effect`
- `oauth_scopes`
- `privilege_class`

For the GitHub governance slice, this note fixes the following interpretation rules:

- `action.provider_id` is always `github`
- `action.action_key` must match the checked-in taxonomy keys from `cmd/agent-auditor-hostd/src/poc/github/taxonomy.rs`
- `method` stays the official HTTP verb from the GitHub REST endpoint docs
- `canonical_resource` stays a redaction-safe resource template, never a raw body, diff hunk, workflow YAML body, or secret value
- `side_effect` describes the externally visible repository or workflow mutation that the endpoint performs
- `oauth_scopes.primary` stores the docs-fixed **required permission** label in the shared auth-label format
- `oauth_scopes.documented` can add the classic OAuth / PAT scope that the endpoint docs still mention
- `privilege_class` stays on the shared `agenta-core` enum; we do not invent GitHub-only privilege classes here

### Auth label encoding inside `oauth_scopes`

GitHub documentation mixes two auth vocabularies:

- fine-grained repository permissions such as **Administration**, **Actions**, **Contents**, and **Secrets**
- classic OAuth / PAT scopes such as `repo`

To keep the checked-in metadata JSON shape stable without pretending every GitHub auth label is literally an OAuth scope, this catalog fixes the following string forms inside `oauth_scopes`:

- `github.permission:<permission>:<access>` for fine-grained PAT / GitHub App-style permission labels
- `github.oauth:<scope>` for classic OAuth / PAT scopes

That gives later policy and audit code one stable auth-label field while still preserving the official docs vocabulary.

### JSON shape fixed for the first GitHub governance slice

```json
{
  "entries": [
    {
      "action": {
        "provider_id": "github",
        "action_key": "pulls.merge"
      },
      "method": "put",
      "canonical_resource": "repos/{owner}/{repo}/pulls/{pull_number}",
      "side_effect": "merges a pull request into the base branch",
      "oauth_scopes": {
        "primary": "github.permission:contents:write",
        "documented": [
          "github.permission:contents:write",
          "github.oauth:repo"
        ]
      },
      "privilege_class": "content_write"
    }
  ]
}
```

The table below fully instantiates that shape for the fixed P9 GitHub governance action set.

## Fixed GitHub governance metadata catalog

| Action key | Official method | Canonical resource | Required permission (official docs) | Observable side effect | Shared auth labels | Privilege class |
| --- | --- | --- | --- | --- | --- | --- |
| `repos.update_visibility` | `PATCH /repos/{owner}/{repo}` | `repos/{owner}/{repo}` | Repository **Administration** permission: `write` | Mutates repository settings and can change repository visibility between public / private / internal modes. | Primary: `github.permission:administration:write`<br>Documented: `github.permission:administration:write`, `github.oauth:repo` | `admin_write` |
| `branches.update_protection` | `PUT /repos/{owner}/{repo}/branches/{branch}/protection` | `repos/{owner}/{repo}/branches/{branch}/protection` | Repository **Administration** permission: `write` | Creates or replaces branch protection rules for the named branch, changing push / merge / review guardrails. | Primary: `github.permission:administration:write`<br>Documented: `github.permission:administration:write`, `github.oauth:repo` | `admin_write` |
| `actions.workflow_dispatch` | `POST /repos/{owner}/{repo}/actions/workflows/{workflow_id}/dispatches` | `repos/{owner}/{repo}/actions/workflows/{workflow_id}` | Repository **Actions** permission: `write` | Creates a `workflow_dispatch` event and schedules a workflow run for the supplied ref / inputs. | Primary: `github.permission:actions:write`<br>Documented: `github.permission:actions:write`, `github.oauth:repo` | `admin_write` |
| `actions.runs.rerun` | `POST /repos/{owner}/{repo}/actions/runs/{run_id}/rerun` | `repos/{owner}/{repo}/actions/runs/{run_id}` | Repository **Actions** permission: `write` | Re-runs the selected workflow run and can create another attempt with new job executions and logs. | Primary: `github.permission:actions:write`<br>Documented: `github.permission:actions:write`, `github.oauth:repo` | `admin_write` |
| `pulls.merge` | `PUT /repos/{owner}/{repo}/pulls/{pull_number}/merge` | `repos/{owner}/{repo}/pulls/{pull_number}` | Repository **Contents** permission: `write` | Merges the pull request into the base branch and updates repository history with a merge / squash / rebase result. | Primary: `github.permission:contents:write`<br>Documented: `github.permission:contents:write`, `github.oauth:repo` | `content_write` |
| `actions.secrets.create_or_update` | `PUT /repos/{owner}/{repo}/actions/secrets/{secret_name}` | `repos/{owner}/{repo}/actions/secrets/{secret_name}` | Repository **Secrets** permission: `write` | Creates or updates an encrypted repository Actions secret that later workflows can consume without exposing the stored secret value. | Primary: `github.permission:secrets:write`<br>Documented: `github.permission:secrets:write`, `github.oauth:repo` | `admin_write` |

## Official source map

### `repos.update_visibility`

- endpoint docs: <https://docs.github.com/en/rest/repos/repos#update-a-repository>
- fine-grained PAT permissions reference: <https://docs.github.com/en/rest/authentication/permissions-required-for-fine-grained-personal-access-tokens>

### `branches.update_protection`

- endpoint docs: <https://docs.github.com/en/rest/branches/branch-protection#update-branch-protection>
- fine-grained PAT permissions reference: <https://docs.github.com/en/rest/authentication/permissions-required-for-fine-grained-personal-access-tokens>

### `actions.workflow_dispatch`

- endpoint docs: <https://docs.github.com/en/rest/actions/workflows#create-a-workflow-dispatch-event>
- fine-grained PAT permissions reference: <https://docs.github.com/en/rest/authentication/permissions-required-for-fine-grained-personal-access-tokens>

### `actions.runs.rerun`

- endpoint docs: <https://docs.github.com/en/rest/actions/workflow-runs#re-run-a-workflow>
- fine-grained PAT permissions reference: <https://docs.github.com/en/rest/authentication/permissions-required-for-fine-grained-personal-access-tokens>

### `pulls.merge`

- endpoint docs: <https://docs.github.com/en/rest/pulls/pulls#merge-a-pull-request>
- fine-grained PAT permissions reference: <https://docs.github.com/en/rest/authentication/permissions-required-for-fine-grained-personal-access-tokens>

### `actions.secrets.create_or_update`

- endpoint docs: <https://docs.github.com/en/rest/actions/secrets#create-or-update-a-repository-secret>
- fine-grained PAT permissions reference: <https://docs.github.com/en/rest/authentication/permissions-required-for-fine-grained-personal-access-tokens>

## Why these six actions

These six actions are the checked-in high-risk GitHub semantic-governance set from P9-2.

Together they cover four governance-heavy mutation families that the earlier GitHub catalog did not pin down tightly enough:

- repository-wide settings changes
- branch policy / merge guardrail changes
- workflow execution triggers and reruns
- merge-path repository history mutation
- repository secret writes

That is enough for later metadata, policy, and record work to prove the GitHub slice against a stable docs-backed action catalog without pretending the rest of the GitHub API is already modeled.

## Deliberate non-goals for this catalog

This note intentionally does **not** claim more than the docs support.

Still out of scope here:

- runtime proof that a live token actually carried the documented permission label
- GraphQL-specific action naming
- issue comments, review comments, review submissions, packages, checks, or org-wide audit-log slices
- any live interception path, fail-closed guarantee, or enforcement claim for GitHub traffic
- GitHub UI-only operations that do not map cleanly onto a fixed REST action identity yet

## Related docs

- phase boundary: [`provider-abstraction-foundation.md`](provider-abstraction-foundation.md)
- GitHub semantic-governance boundary: [`hostd-github-semantic-governance-poc.md`](hostd-github-semantic-governance-poc.md)
- local runbook: [`../runbooks/provider-abstraction-foundation-local.md`](../runbooks/provider-abstraction-foundation-local.md)
- known constraints: [`provider-abstraction-known-constraints.md`](provider-abstraction-known-constraints.md)
- architecture overview: [`overview.md`](overview.md)
- GWS action catalog: [`hostd-api-network-gws-action-catalog.md`](hostd-api-network-gws-action-catalog.md)
- shared provider contract and metadata types: [`../../crates/agenta-core/src/provider.rs`](../../crates/agenta-core/src/provider.rs)
- roadmap mirror: [`../roadmaps/provider-abstraction-foundation-tasklist.md`](../roadmaps/provider-abstraction-foundation-tasklist.md)
