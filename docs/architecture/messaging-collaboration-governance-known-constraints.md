# messaging / collaboration governance: known constraints

This note records the current constraints of the repository-wide messaging / collaboration governance slice.

## Current limitations

1. **No live Slack / Discord interception seam yet**
   - the current local path does not intercept real Slack or Discord traffic yet
   - bootstrap output is produced from deterministic preview events assembled in userspace
   - there is no validated bot mediation layer, webhook gateway, browser relay, or inline API pause/resume seam behind the messaging preview today

2. **The messaging layer still depends on upstream provider taxonomy and generic REST lineage**
   - upstream provider taxonomy still decides `provider_id`, `action_key`, redaction-safe `target_hint`, and semantic-surface hints
   - the generic REST layer still supplies method / host / path / query / auth / privilege descriptors
   - the messaging layer does not classify arbitrary provider traffic on its own

3. **Coverage is intentionally tiny**
   - the checked-in preview posture is still represented by a six-action sample:
     - Slack `chat.post_message`
     - Slack `conversations.invite`
     - Slack `files.upload_v2`
     - Discord `channels.messages.create`
     - Discord `channels.thread_members.put`
     - Discord `channels.permissions.put`
   - this is enough to stabilize the messaging contract and record shape, not enough to claim broad provider coverage

4. **Collaboration-family coverage is intentionally narrow**
   - the checked-in shared messaging taxonomy only proves four action families:
     - `message.send`
     - `channel.invite`
     - `permission.update`
     - `file.upload`
   - it does not yet cover direct messages, private-group nuances, reactions, thread lifecycle actions, channel creation/archival, moderation actions, or richer collaboration workflows

5. **Permission labels are docs-backed, not runtime-verified**
   - the current repository proves that metadata can describe expected Slack scope labels or Discord permission labels for an action
   - it does not inspect live OAuth grants, bot permissions, delegated identity, channel membership, or runtime auth failures before producing the messaging record

6. **Redaction is deliberate and lossy**
   - the messaging seam intentionally keeps action family, provider lineage, target hints, channel / conversation hints, delivery scope, target kinds, attachment-count hints, and docs-backed auth/risk descriptors only
   - it does **not** carry raw message bodies, embeds, thread history, participant rosters, invite links, uploaded file bytes, preview URLs, OCR output, or provider-specific opaque payloads
   - this is the right safety boundary, but it also means some downstream nuance is intentionally unavailable in the shared messaging layer

7. **Policy behavior is intentionally narrow**
   - the checked-in preview policy is `examples/policies/messaging_action.rego`
   - the default path proves only these outcomes:
     - public-channel message send -> `allow`
     - membership expansion -> `require_approval`
     - permission overwrite update -> `deny`
     - file upload -> `require_approval`
   - it is not yet a complete messaging / collaboration governance model

8. **Approval flow stops at record creation**
   - `require_approval` currently enriches the event metadata and creates a pending `ApprovalRequest`
   - there is no approval inbox, reviewer workflow, callback into a live Slack / Discord adapter, or resumed provider execution after approval yet

9. **Persistence is bootstrap-local and resettable**
   - messaging audit records and approval requests are appended to JSONL under `target/agent-auditor-hostd-messaging-poc-store/`
   - the PoC store resets that directory on bootstrap, so this is not durable product storage yet
   - there is no lookup API, retention policy, compaction, replay support, or multi-process coordination

10. **Smoke coverage is fixture-backed on purpose**
    - the dedicated messaging smoke test validates stable bootstrap preview output for normalized events, policy decisions, approval requests, and persisted records
    - the broader provider-abstraction and generic REST smoke tests validate the upstream preview slices that feed the messaging contract
    - none of this is evidence that the same behavior has been validated against live Slack or Discord traffic, real bot permissions, or production gateway integration

11. **No messaging action is inside a validated fail-closed subset yet**
    - the current bootstrap can reflect intended `hold` and `deny` outcomes into event metadata and local records
    - it does not yet prove a live Slack or Discord action can be paused or blocked inline at the messaging seam
    - fail-open / fail-closed claims still belong to a future validated runtime mediation path, not to the existence of the messaging contract itself

12. **Control-plane UX is still ahead of this phase**
    - the messaging slice now proves action-family taxonomy, normalized contract fields, preview policy outcomes, approval requests, and local audit records
    - it does not yet expose a reviewer inbox, policy explainability UX, notification fanout, reconciliation flow, or product-grade approval controls
    - those operator-facing concerns are intentionally left for P12 instead of being smuggled into the messaging slice prematurely

## Practical interpretation

Today’s messaging / collaboration governance slice is good for:

- stabilizing the ownership split between provider taxonomy, generic REST lineage, messaging taxonomy, policy, and record reflection
- proving a checked-in provider-neutral messaging contract in `agenta-core`
- proving that `agenta-policy` can evaluate `input.messaging_action`
- proving a first shared collaboration taxonomy across a minimal Slack / Discord action sample
- proving reflected allow / hold / deny metadata shapes for local event, approval, and audit records
- proving local persistence and smoke-test coverage for the bootstrap preview contract
- giving P12 a stable action-family surface to build approval / control-plane UX on top of

It is **not yet** good evidence of:

- production-ready Slack / Discord interception or mediation
- runtime verification of Slack scopes, Discord permissions, or membership state
- comprehensive messaging / collaboration coverage
- content-aware moderation, DLP, or file inspection
- product-grade approval orchestration
- durable product storage for messaging audit or approval records
- validated fail-closed behavior on live messaging actions

## Related docs

- phase boundary: [`messaging-collaboration-governance-foundation.md`](messaging-collaboration-governance-foundation.md)
- action catalog: [`messaging-collaboration-action-catalog.md`](messaging-collaboration-action-catalog.md)
- local runbook: [`../runbooks/messaging-collaboration-governance-local.md`](../runbooks/messaging-collaboration-governance-local.md)
- generic REST / OAuth boundary: [`generic-rest-oauth-governance-foundation.md`](generic-rest-oauth-governance-foundation.md)
- generic REST / OAuth constraints: [`generic-rest-oauth-governance-known-constraints.md`](generic-rest-oauth-governance-known-constraints.md)
- provider abstraction boundary: [`provider-abstraction-foundation.md`](provider-abstraction-foundation.md)
- architecture overview: [`overview.md`](overview.md)
