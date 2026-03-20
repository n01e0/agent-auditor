# hostd API / network GWS PoC: known constraints

This note records the current constraints of the `agent-auditor-hostd` API / network Google Workspace PoC after the first semantic-action slice.

## Current limitations

1. **No live API/browser/network capture yet**
   - the PoC names `api_observation` and `network_observation` seams, but the documented local path does not intercept real Google Workspace requests yet
   - current bootstrap output is produced from deterministic preview observations assembled in userspace

2. **Session linkage is still provisional**
   - the current linkage contract proves that API/network hints can be bound to the same session model used elsewhere in hostd
   - it does not yet prove how a real request adapter, browser relay, proxy, or egress observer will supply correlation ids on a live host

3. **Semantic coverage is intentionally tiny**
   - the preview taxonomy only proves four actions:
     - `drive.permissions.update`
     - `drive.files.get_media`
     - `gmail.users.messages.send`
     - `admin.reports.activities.list`
   - it does not yet cover broader Drive read/write surfaces, Gmail drafts, Calendar, Docs, Meet, Chat, Admin mutations, or non-GWS SaaS APIs

4. **Classification depends on redaction-safe request hints only**
   - the current classifier uses method, authority, path, destination metadata, and a small amount of query-shape reasoning
   - it does not inspect raw HTTP bodies, response payloads, email content, document content, or browser DOM state

5. **OAuth scope handling is documentation-fixed, not runtime-verified**
   - the checked-in action catalog fixes a canonical scope per semantic action for docs and future policy clarity
   - the current runtime preview does not inspect real OAuth tokens, granted scopes, delegated subject identity, or Google API auth failures

6. **Policy behavior is intentionally narrow**
   - the checked-in preview policy is `examples/policies/gws_action.rego`
   - the default path proves only these outcomes:
     - Drive permission updates -> `require_approval`
     - Drive content download -> `require_approval`
     - Gmail send -> `require_approval`
     - Admin activity listing -> `allow`
   - it is not yet a complete Google Workspace governance model

7. **No GWS action is inside a validated fail-closed subset yet**
   - `drive.permissions.update`, `drive.files.get_media`, and `gmail.users.messages.send` now have documented `approval_hold_preview` posture and reflected hold metadata, but they still fail open for live execution
   - `admin.reports.activities.list` stays `observe_only_allow_preview`, so it is visible in policy and audit records without any deny/hold runtime claim
   - the per-action failure-behavior matrix lives in [`hostd-api-network-gws-action-catalog.md`](hostd-api-network-gws-action-catalog.md)

8. **No live deny or hold path for GWS actions yet**
   - the preview path can reflect `allow`, synthetic `deny`, and `require_approval` into event metadata and JSONL records
   - it does not yet stop a real API request before completion, hold an in-flight action, or resume work after approval resolution

9. **Approval flow stops at record creation**
   - `require_approval` currently enriches the event metadata and creates a pending `ApprovalRequest`
   - there is no approval inbox, reviewer workflow, callback into a GWS adapter, or resumed API execution after approval yet

10. **Persistence is bootstrap-local and resettable**
   - GWS audit records and approval requests are appended to JSONL under `target/agent-auditor-hostd-gws-poc-store/`
   - the PoC store resets that directory on bootstrap, so this is not durable product storage yet
   - there is no lookup API, retention policy, compaction, replay support, or multi-process coordination

11. **Fixture-backed and consistency smoke coverage is intentional**
    - the dedicated GWS smoke tests validate stable bootstrap preview output plus agreement between hold / deny / observe-only projections and persisted records
    - the targeted approval-path unit tests validate posture gating, missing semantic-action handling, and decision-shape rejection
    - none of this is evidence that the same behavior has been validated against live Google Workspace traffic, real OAuth grants, or production admin tenants

12. **Linux-local and single-host assumptions still apply**
    - this path assumes Linux and a Rust development workflow
    - host hardening, proxy deployment, browser integration, tenant setup, service-account management, and cross-host coordination are still outside this runbook-level PoC

## Practical interpretation

Today’s GWS PoC is good for:

- stabilizing the internal session_linkage / classify / evaluate / record split
- proving the shape of normalized `gws_action` events
- proving a first semantic taxonomy for four Google Workspace actions
- proving a narrow Rego decision path with `allow` / `require_approval`
- proving reflected hold/deny metadata shape for local event, approval, and audit records
- proving approval-request creation and local audit-record inspection
- proving that the approval-path and GWS smoke tests stay aligned with the checked-in preview contract
- keeping CI coverage around the current API/network GWS design

It is **not yet** good evidence of:

- production-ready Google Workspace interception
- robust real-world session correlation across adapters and network observers
- comprehensive Google Workspace semantic coverage
- runtime OAuth-scope verification
- fail-closed or inline-hold safety on live Google Workspace requests
- durable product-grade audit storage or approval orchestration

## Related docs

- module boundary: [`hostd-api-network-gws-poc.md`](hostd-api-network-gws-poc.md)
- action catalog: [`hostd-api-network-gws-action-catalog.md`](hostd-api-network-gws-action-catalog.md)
- local runbook: [`../runbooks/hostd-api-network-gws-poc-local.md`](../runbooks/hostd-api-network-gws-poc-local.md)
- failure behavior policy: [`failure-behavior.md`](failure-behavior.md)
- coverage matrix: [`coverage-matrix.md`](coverage-matrix.md)
- product requirements: [`../PRD.md`](../PRD.md)
