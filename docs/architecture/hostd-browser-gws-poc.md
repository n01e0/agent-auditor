# hostd browser / GWS phase boundary

This note fixes the first internal split for the `agent-auditor-hostd` browser / Google Workspace expansion.

## Goal of P6-1

Keep the browser / GWS slice honest about ownership before minimal session linkage, GWS semantic-action taxonomy, normalized `agenta-core` events, policy wiring, and durable audit / approval storage land.

The immediate rule is:

- **session_linkage** owns attaching browser-originated activity to the same session identity used by runtime hostd events
- **classify** owns turning session-linked browser context into semantic browser / GWS action candidates
- **evaluate** owns `agenta-core` normalization, `agenta-policy` bridging, and approval-gate projection
- **record** owns durable audit / approval persistence and publish fanout
- the shared seams are a small session_linkage → classify contract, a small classify → evaluate contract, and a small evaluate → record contract that all preserve the same browser redaction rule

Unlike the filesystem, network, and secret PoCs, browser / GWS needs an explicit **session_linkage** stage ahead of classification. Browser signals are not useful for policy until they are tied back to the agent session that opened the tab or drove the action.

The redaction rule for this phase is also explicit from the start: raw page bodies, email bodies, and document contents must not cross the browser boundary seams. The Phase 2 browser layer should operate on semantic action hints, target hints, and session context rather than arbitrary page content capture.

## Code layout

`cmd/agent-auditor-hostd/src/poc/browser/`

- `contract.rs`
  - shared seams between session_linkage → classify, classify → evaluate, and evaluate → record
  - supported browser signal sources and semantic-surface labels
- `session_linkage.rs`
  - browser-origin to session-identity boundary plan
  - future home for minimal browser session linkage contract work
- `classify.rs`
  - semantic browser / GWS action classification plan after linkage
  - future home for browser and Google Workspace semantic taxonomy
- `evaluate.rs`
  - normalization + policy bridge plan after classification
  - future home for `agenta-core` browser / GWS event shaping and `agenta-policy` evaluation
- `record.rs`
  - audit / approval record plan after evaluation
  - future home for append-only storage and publish fanout
- `mod.rs`
  - assembles the browser / GWS phase plan and tests the split

## Responsibility split

### Session linkage

Owns:

- accepting browser-originated action hints from relay and automation surfaces
- linking browser session, tab, frame, and document context to the same `session_id` model used by runtime events
- preserving top-level origin, document URL / title hints, and semantic-surface hints for downstream classification
- handing off session-linked browser action candidates without normalizing `agenta-core` events or choosing semantic taxonomy

Does **not** own:

- GWS semantic action taxonomy
- `agenta-core` normalization
- Rego / `agenta-policy` evaluation
- durable audit or approval persistence

### Classify

Owns:

- accepting session-linked browser action candidates after identity resolution is done
- classifying generic browser and Google Workspace context into semantic action candidates and target hints
- attaching classifier labels and rationale while keeping raw browser content out of the seam
- handing off classified semantic actions downstream

Does **not** own:

- browser-to-session identity correlation
- `agenta-core` event normalization
- policy evaluation
- durable audit storage

### Evaluate

Owns:

- normalizing classified browser / GWS semantic candidates toward `agenta-core`
- bridging normalized browser semantic actions into `agenta-policy`
- projecting `allow` / `deny` / `require_approval` plus approval-request candidates for recording
- carrying the browser redaction contract forward into the record stage

Does **not** own:

- browser instrumentation or session-linkage mechanics
- semantic taxonomy heuristics
- durable audit storage
- durable approval storage or publish fanout

### Record

Owns:

- appending redaction-safe browser / GWS audit records
- appending approval requests created by approval-gated browser semantic actions
- publishing recorded artifacts to logs and later control-plane sinks

Does **not** own:

- session linkage
- semantic classification heuristics
- policy evaluation or approval decision logic
- recovering raw page, email, or document contents for storage or display

## Supported boundary labels in P6-1

The boundary is intentionally small but explicit about the labels it will carry forward:

- signal sources:
  - `extension_relay`
  - `automation_bridge`
- semantic surfaces:
  - `browser`
  - `gws.drive`
  - `gws.gmail`
  - `gws.admin`

These are boundary labels, not the final action taxonomy. Concrete actions such as `drive.change_sharing`, `drive.download_file`, `gmail.send_message`, and `admin.open_surface` are deferred to later tasks.

## Why this split now

This keeps the next tasks cleaner:

- **P6-2** can implement minimal browser action session linkage against a stable upstream seam
- **P6-3** can add GWS semantic taxonomy without deciding how normalization or audit persistence work
- **P6-4** can shape classified browser candidates into `agenta-core` events without owning taxonomy or linkage heuristics
- **P6-5** can wire browser / GWS policy evaluation against a stable evaluate seam
- **P6-6 / P6-7** can reflect decisions and test audit behavior without reaching back into linkage or classification internals

## Explicitly out of scope for P6-1

- concrete browser instrumentation or browser-extension protocol details
- the minimal session-linkage implementation itself
- concrete GWS semantic action taxonomy rules
- concrete `agenta-core` browser / GWS event normalization
- concrete `agenta-policy` evaluation
- durable audit / approval persistence implementation
- arbitrary site semantic parsing outside the initial GWS scope
- full runbook / operator UX work

## Related docs

- architecture overview: [`overview.md`](overview.md)
- product requirements: [`../PRD.md`](../PRD.md)
- coverage matrix: [`coverage-matrix.md`](coverage-matrix.md)
- enforcement foundation: [`hostd-enforcement-foundation.md`](hostd-enforcement-foundation.md)
- secret-access boundary reference: [`hostd-secret-access-poc.md`](hostd-secret-access-poc.md)
