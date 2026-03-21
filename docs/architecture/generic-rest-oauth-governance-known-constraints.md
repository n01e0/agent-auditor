# generic REST / OAuth governance: known constraints

This note records the current constraints of the repository-wide generic REST / OAuth governance slice.

## Current limitations

1. **No live generic REST interception seam yet**
   - the current local path does not intercept real provider REST traffic yet
   - bootstrap output is produced from deterministic preview events assembled in userspace
   - there is no validated proxy, sidecar, browser relay, or API mediation seam behind the generic REST preview today

2. **The generic layer still depends on upstream provider taxonomy and metadata**
   - provider-specific taxonomy still decides `provider_id`, `action_key`, and redaction-safe `target_hint`
   - provider metadata still supplies docs-backed method / canonical resource / scope / side-effect / privilege descriptors
   - the generic REST layer does not classify arbitrary provider traffic on its own

3. **Coverage is intentionally tiny**
   - the generic contract is repository-wide, but the checked-in preview posture is still represented by a tiny cross-provider sample:
     - GWS admin activity listing
     - GWS Gmail send
     - GitHub Actions secret create/update
   - this is enough to stabilize the contract and record shape, not enough to claim broad provider coverage

4. **The contract covers REST/OAuth descriptors, not every governance shape**
   - the checked-in generic contract is about `method`, `host`, `path_template`, `query_class`, `oauth_scope_labels`, `side_effect`, and `privilege_class`
   - it does not yet cover GraphQL-specific semantics, webhook payload semantics, message-body-specific governance, browser-only UI actions, or other higher-level product actions that do not map cleanly onto the generic REST seam

5. **Auth labels are docs-backed, not runtime-verified**
   - the current repository proves that metadata can describe expected OAuth scope labels or permission labels for an action
   - it does not inspect live token grants, delegated subject identity, installation permissions, or runtime auth failures before producing the generic REST record

6. **Redaction is deliberate and lossy**
   - the generic REST seam intentionally keeps route templates, authority labels, query classes, shared action identity, target hints, and docs-backed auth/risk descriptors only
   - it does **not** carry raw request bodies, response bodies, full query strings, token values, message bodies, file bytes, signed URLs, or provider-specific opaque payloads
   - this is the right safety boundary, but it also means some downstream nuance is intentionally unavailable in the generic layer

7. **Policy behavior is intentionally narrow**
   - the checked-in preview policy is `examples/policies/generic_rest_action.rego`
   - the default path proves only three outcome families:
     - read-only audit listing -> `allow`
     - outbound send -> `require_approval`
     - GitHub secret write -> `deny`
   - it is not yet a complete cross-provider REST / OAuth governance model

8. **Approval flow stops at record creation**
   - `require_approval` currently enriches the event metadata and creates a pending `ApprovalRequest`
   - there is no approval inbox, reviewer workflow, callback into a live provider adapter, or resumed provider execution after approval yet

9. **Persistence is bootstrap-local and resettable**
   - generic REST audit records and approval requests are appended to JSONL under `target/agent-auditor-hostd-generic-rest-poc-store/`
   - the PoC store resets that directory on bootstrap, so this is not durable product storage yet
   - there is no lookup API, retention policy, compaction, replay support, or multi-process coordination

10. **Smoke coverage is fixture-backed on purpose**
    - the dedicated generic REST smoke test validates stable bootstrap preview output for normalized events, policy decisions, approval requests, and persisted records
    - the broader provider-abstraction, GWS, and GitHub smoke tests validate the upstream preview slices that feed the generic contract
    - none of this is evidence that the same behavior has been validated against live provider traffic or real token grants

11. **No generic REST action is inside a validated fail-closed subset yet**
    - the current bootstrap can reflect intended `hold` and `deny` outcomes into event metadata and local records
    - it does not yet prove a live provider request can be paused or blocked inline at the generic REST seam
    - fail-open / fail-closed claims still belong to a future validated runtime interception path, not to the existence of the generic contract itself

12. **Messaging / collaboration semantics are still ahead of this phase**
    - the generic REST contract is meant to become a lower-level substrate for later messaging / collaboration governance where REST / OAuth semantics still apply
    - it does not yet model action families like `message.send`, `channel.invite`, `permission.update`, or `file.upload`
    - those higher-level semantics are intentionally left for P11 instead of being smuggled into the generic REST layer prematurely

## Practical interpretation

Today’s generic REST / OAuth governance slice is good for:

- stabilizing the ownership split between provider taxonomy, provider metadata, generic REST normalization, policy, and record reflection
- proving a checked-in provider-neutral REST contract in `agenta-core`
- proving that `agenta-policy` can evaluate `input.generic_rest_action`
- proving reflected allow / hold / deny metadata shapes for local event, approval, and audit records
- proving local persistence and smoke-test coverage for the bootstrap preview contract
- giving later messaging / collaboration work a lower-level REST / OAuth seam to build on

It is **not yet** good evidence of:

- production-ready cross-provider REST interception
- runtime verification of OAuth grants or provider permissions
- comprehensive provider coverage
- product-grade approval orchestration
- durable product storage for generic REST audit or approval records
- validated fail-closed behavior on live provider requests
- message- or collaboration-specific governance semantics above the REST seam

## Related docs

- phase boundary: [`generic-rest-oauth-governance-foundation.md`](generic-rest-oauth-governance-foundation.md)
- local runbook: [`../runbooks/generic-rest-oauth-governance-local.md`](../runbooks/generic-rest-oauth-governance-local.md)
- provider abstraction boundary: [`provider-abstraction-foundation.md`](provider-abstraction-foundation.md)
- provider abstraction constraints: [`provider-abstraction-known-constraints.md`](provider-abstraction-known-constraints.md)
- GitHub semantic governance constraints: [`hostd-github-semantic-governance-known-constraints.md`](hostd-github-semantic-governance-known-constraints.md)
- architecture overview: [`overview.md`](overview.md)
