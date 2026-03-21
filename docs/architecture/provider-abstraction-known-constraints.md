# provider abstraction foundation: known constraints

This note records the current constraints of the repository-wide provider-abstraction foundation slice.

## Current limitations

1. **Only the shared contract and metadata model are cross-provider today**
   - the repository now has provider-common identity and metadata types in `agenta-core`
   - that does **not** mean every provider has a runtime implementation, classifier, adapter, or enforcement path

2. **The live checked-in runtime path is still GWS-backed**
   - the current end-to-end preview that populates shared provider fields comes from `cmd/agent-auditor-hostd/src/poc/gws/`
   - the provider-abstraction smoke output is therefore proof that the shared contract works with the current GWS slice, not proof of a generalized multi-provider runtime

3. **GitHub is taxonomy- and metadata-fixed, not runtime-implemented**
   - `provider-abstraction-github-candidate-catalog.md` now fixes the first six GitHub governance action keys plus docs-backed method / resource / required permission / side effect descriptors
   - `cmd/agent-auditor-hostd/src/poc/github/taxonomy.rs` classifies those six high-risk GitHub governance actions in a redaction-safe PoC taxonomy seam
   - there is still no checked-in normalized GitHub event path, policy example, or hostd preview flow for those actions

4. **Provider-specific taxonomy still lives in provider modules**
   - the abstraction boundary deliberately leaves provider-native matching heuristics in provider adapters and PoC modules
   - only the action identity and metadata contract are shared today
   - there is not yet a generic provider-plugin runtime or registry that can classify arbitrary providers by itself

5. **Runtime metadata coverage is intentionally tiny**
   - the preview metadata catalog currently covers the four checked-in GWS actions:
     - `drive.permissions.update`
     - `drive.files.get_media`
     - `gmail.users.messages.send`
     - `admin.reports.activities.list`
   - the GitHub catalog now fixes six docs-backed governance actions:
     - `repos.update_visibility`
     - `branches.update_protection`
     - `actions.workflow_dispatch`
     - `actions.runs.rerun`
     - `pulls.merge`
     - `actions.secrets.create_or_update`
   - that is enough to stabilize the shape, not enough to claim broad provider coverage

6. **`oauth_scopes` is currently a stable label container, not a perfect auth model**
   - for GWS, the field carries docs-backed OAuth scope labels
   - for GitHub, the same field intentionally carries docs-backed fine-grained permission labels and classic OAuth/PAT scopes using prefixed strings
   - this keeps the JSON shape stable now, but it is not yet a separate first-class type system for every provider auth model

7. **Auth labels are docs-backed, not runtime-verified**
   - the current repository proves that metadata can describe the expected auth label shape for an action
   - it does not inspect live OAuth grants, fine-grained token permissions, delegated subject identity, installation permissions, or auth failures at runtime

8. **Policy generalization is narrower than provider implementation**
   - `agenta-policy` now evaluates on provider + action identity through `input.provider_action`
   - the checked-in example policy is still the GWS preview policy, not a general provider policy pack that already covers GitHub or other providers

9. **Bootstrap preview output is deterministic and repository-local**
   - the provider-abstraction smoke test validates stable bootstrap lines from `agent-auditor-hostd`
   - that output is still repository-owned preview output, not a durable provider catalog API or a remote control-plane contract

10. **No provider-abstraction layer is fail-closed by itself**
    - the shared contract and shared metadata shape describe actions; they do not enforce them
    - any fail-open / fail-closed claim still belongs to a concrete provider runtime path, not to the existence of `provider_id`, `action_key`, or docs-backed metadata alone

11. **Fixture-backed coverage is intentional**
    - the provider abstraction slice is covered by unit tests and a dedicated smoke test that pin the bootstrap preview contract
    - that is evidence of internal consistency, not evidence of validation against live GitHub traffic, real tenant auth, or production browser / proxy integration

12. **UI, API, and storage generalization are still ahead of this phase**
    - the repository now has shared action identity and metadata types plus provider-aware policy input
    - it does not yet expose a product-grade provider catalog API, provider-agnostic approval UX, or durable multi-provider metadata storage beyond the current checked-in code/docs path

## Practical interpretation

Today’s provider-abstraction foundation is good for:

- stabilizing the ownership split between provider taxonomy, shared contract, and shared metadata
- proving a provider-neutral action identity in `agenta-core`
- proving a provider-neutral metadata shape in `agenta-core`
- proving that GWS can populate the shared provider contract end to end
- proving that `agenta-policy` can evaluate on provider + action identity
- fixing the first GitHub governance action metadata catalog in docs
- keeping CI coverage around the current shared contract / metadata / smoke-test agreement

It is **not yet** good evidence of:

- a production-ready multi-provider runtime
- a checked-in GitHub provider implementation
- runtime auth-grant verification across providers
- comprehensive provider taxonomies or catalogs
- provider-agnostic fail-closed enforcement
- durable remote catalog distribution or productized provider-management APIs

## Related docs

- phase boundary: [`provider-abstraction-foundation.md`](provider-abstraction-foundation.md)
- local runbook: [`../runbooks/provider-abstraction-foundation-local.md`](../runbooks/provider-abstraction-foundation-local.md)
- GitHub candidate catalog: [`provider-abstraction-github-candidate-catalog.md`](provider-abstraction-github-candidate-catalog.md)
- GWS action catalog: [`hostd-api-network-gws-action-catalog.md`](hostd-api-network-gws-action-catalog.md)
- architecture overview: [`overview.md`](overview.md)
- roadmap mirror: [`../roadmaps/provider-abstraction-foundation-tasklist.md`](../roadmaps/provider-abstraction-foundation-tasklist.md)
