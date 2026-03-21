# hostd GitHub semantic governance PoC: known constraints

This note records the current constraints of the `agent-auditor-hostd` GitHub semantic-governance PoC after the first GitHub slice.

## Current limitations

1. **No live GitHub API/browser/proxy capture yet**
   - the PoC names `api_observation` and `browser_observation` seams, but the documented local path does not intercept real GitHub requests yet
   - current bootstrap output is produced from deterministic preview observations assembled in userspace

2. **Upstream session attribution is still assumed, not proven**
   - the GitHub boundary expects upstream adapters to supply session ownership before taxonomy begins
   - the current local preview does not yet prove how a real browser relay, proxy adapter, or API mediation path will bind GitHub requests back to a live session on a host

3. **Semantic coverage is intentionally tiny**
   - the preview taxonomy only proves six actions:
     - `repos.update_visibility`
     - `branches.update_protection`
     - `actions.workflow_dispatch`
     - `actions.runs.rerun`
     - `pulls.merge`
     - `actions.secrets.create_or_update`
   - it does not yet cover repository contents, issue/comment workflows, release management, checks, packages, org-level settings, or broader GitHub admin surfaces

4. **Classification depends on redaction-safe request hints only**
   - the current classifier uses method, authority, route-template, path, target-hint, and semantic-surface hints
   - it does not inspect raw HTTP bodies, issue bodies, pull-request bodies, diff hunks, workflow YAML bodies, secret values, or browser DOM state
   - `repos.update_visibility` currently depends on a redaction-safe visibility target hint because the bare `PATCH /repos/{owner}/{repo}` path alone is not specific enough

5. **Permission labels are docs-backed, not runtime-verified**
   - the checked-in GitHub metadata catalog fixes canonical required-permission labels and classic OAuth/PAT scope strings for the six actions
   - the current runtime preview does not inspect live PAT grants, GitHub App installation permissions, delegated subject identity, or real GitHub auth failures

6. **Policy behavior is intentionally narrow**
   - the checked-in preview policy is `examples/policies/github_action.rego`
   - the default path proves only these outcomes:
     - repository visibility updates -> `require_approval`
     - branch protection updates -> `require_approval`
     - workflow dispatch -> `require_approval`
     - workflow rerun -> `allow`
     - pull-request merge -> `require_approval`
     - repository Actions secret write -> `deny`
   - it is not yet a complete GitHub governance model

7. **No GitHub action is inside a validated fail-closed subset yet**
   - `repos.update_visibility`, `branches.update_protection`, `actions.workflow_dispatch`, and `pulls.merge` now have reflected `hold` metadata, but they still fail open for live execution
   - `actions.secrets.create_or_update` now has reflected `deny` metadata, but there is still no validated inline GitHub request block path
   - `actions.runs.rerun` stays observe-only/allow in the checked-in posture, so there is currently no hold/deny runtime claim to make for that action

8. **Approval flow stops at record creation**
   - `require_approval` currently enriches the event metadata and creates a pending `ApprovalRequest`
   - there is no approval inbox, reviewer workflow, callback into a GitHub adapter, or resumed GitHub execution after approval yet

9. **Persistence is bootstrap-local and resettable**
   - GitHub audit records and approval requests are appended to JSONL under `target/agent-auditor-hostd-github-poc-store/`
   - the PoC store resets that directory on bootstrap, so this is not durable product storage yet
   - there is no lookup API, retention policy, compaction, replay support, or multi-process coordination

10. **Smoke coverage is fixture-backed on purpose**
    - the dedicated GitHub smoke test validates stable bootstrap preview output for normalized events, policy decisions, approval requests, and persisted records
    - the broader provider-abstraction smoke test validates that the shared provider contract still agrees with the current GitHub slice
    - none of this is evidence that the same behavior has been validated against live GitHub traffic, real token grants, or production browser/proxy integration

11. **Provider abstraction is still narrower than provider implementation**
    - the repository now proves GitHub taxonomy, docs-backed metadata, normalized events, preview policy outcomes, and append-only preview records
    - it does not yet expose a production GitHub mediation service, a provider catalog API, or a provider-agnostic approval UX for these actions

12. **Linux-local and single-host assumptions still apply**
    - this path assumes Linux and a Rust development workflow
    - host hardening, proxy deployment, browser integration, GitHub App setup, PAT management, and cross-host coordination are still outside this runbook-level PoC

## Practical interpretation

Today’s GitHub PoC is good for:

- stabilizing the internal taxonomy / metadata / policy / record split for GitHub governance
- proving a first semantic taxonomy for six high-risk GitHub governance actions
- proving docs-backed GitHub action metadata for method / canonical resource / permission / side effect
- proving normalized `github_action` events in `agenta-core`
- proving a narrow Rego decision path with `allow` / `require_approval` / `deny`
- proving reflected hold/deny metadata shape for local event, approval, and audit records
- proving approval-request creation and local audit-record inspection
- proving that the GitHub unit tests and smoke test stay aligned with the checked-in preview contract

It is **not yet** good evidence of:

- production-ready GitHub interception or mediation
- robust real-world session correlation across adapters and browser/proxy observers
- comprehensive GitHub semantic coverage
- runtime verification of PAT scopes or GitHub App permissions
- fail-closed or inline-hold safety on live GitHub requests
- durable product-grade audit storage or approval orchestration

## Related docs

- module boundary: [`hostd-github-semantic-governance-poc.md`](hostd-github-semantic-governance-poc.md)
- GitHub metadata catalog: [`provider-abstraction-github-candidate-catalog.md`](provider-abstraction-github-candidate-catalog.md)
- local runbook: [`../runbooks/hostd-github-semantic-governance-poc-local.md`](../runbooks/hostd-github-semantic-governance-poc-local.md)
- provider-abstraction constraints: [`provider-abstraction-known-constraints.md`](provider-abstraction-known-constraints.md)
- failure behavior policy: [`failure-behavior.md`](failure-behavior.md)
- coverage matrix: [`coverage-matrix.md`](coverage-matrix.md)
- product requirements: [`../PRD.md`](../PRD.md)
