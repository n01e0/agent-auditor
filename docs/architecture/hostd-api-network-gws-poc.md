# hostd API / network GWS phase boundary

This note fixes the first internal split for the `agent-auditor-hostd` API / network Google Workspace semantic-action expansion.

## Goal of P6A-1

Keep the API / network GWS slice honest about ownership before minimal session linkage, GWS semantic-action taxonomy, normalized `agenta-core` events, policy wiring, and durable audit / approval storage land.

The immediate rule is:

- **session_linkage** owns attaching API- and network-originated activity to the same session identity used by runtime hostd events
- **classify** owns turning session-linked request / egress context into semantic GWS action candidates
- **evaluate** owns `agenta-core` normalization, `agenta-policy` bridging, and approval-gate projection
- **record** owns durable audit / approval persistence and publish fanout
- the shared seams are a small session_linkage → classify contract, a small classify → evaluate contract, and a small evaluate → record contract that all preserve the same GWS redaction rule

Unlike the filesystem, network, and secret PoCs, the API / network GWS phase needs an explicit **session_linkage** stage ahead of classification. API metadata and network tuples are not useful for policy until they are tied back to the agent session that issued the request or drove the side effect.

The redaction rule for this phase is also explicit from the start: raw HTTP request or response payloads, email bodies, and document contents must not cross the GWS boundary seams. The Phase 2 GWS layer should operate on method / authority / path hints, destination hints, semantic action hints, and session context rather than arbitrary payload capture.

## Code layout

`cmd/agent-auditor-hostd/src/poc/gws/`

- `contract.rs`
  - shared seams between session_linkage → classify, classify → evaluate, and evaluate → record
  - supported API/network signal-source labels and GWS surface labels
- `session_linkage.rs`
  - API / network origin to session-identity boundary plan
  - future home for minimal GWS session linkage contract work
- `classify.rs`
  - semantic GWS action classification plan after linkage
  - future home for GWS API / network semantic taxonomy
- `evaluate.rs`
  - normalization + policy bridge plan after classification
  - future home for `agenta-core` GWS event shaping and `agenta-policy` evaluation
- `record.rs`
  - audit / approval record plan after evaluation
  - future home for append-only storage and publish fanout
- `mod.rs`
  - assembles the API / network GWS phase plan and tests the split

## Responsibility split

### Session linkage

Owns:

- accepting API- and network-originated action hints from request adapters and egress observation surfaces
- linking request ids, authority / path hints, destination metadata, and GWS surface hints to the same `session_id` model used by runtime events
- preserving session-linked request context without deciding the final semantic action taxonomy
- handing off session-linked API / network action candidates without normalizing `agenta-core` events or choosing policy outcome

Does **not** own:

- GWS semantic action taxonomy
- `agenta-core` normalization
- Rego / `agenta-policy` evaluation
- durable audit or approval persistence

### Classify

Owns:

- accepting session-linked API / network action candidates after identity resolution is done
- classifying GWS request and egress context into semantic action candidates and target hints
- attaching classifier labels and rationale while keeping raw payloads and document / message content out of the seam
- handing off classified semantic actions downstream

Does **not** own:

- session identity correlation
- `agenta-core` event normalization
- policy evaluation
- durable audit storage

### Evaluate

Owns:

- normalizing classified GWS semantic candidates toward `agenta-core`
- bridging normalized GWS semantic actions into `agenta-policy`
- projecting `allow` / `deny` / `require_approval` plus approval-request candidates for recording
- carrying the GWS redaction contract forward into the record stage

Does **not** own:

- API adapters, egress observation, or session-linkage mechanics
- semantic taxonomy heuristics
- durable audit storage
- durable approval storage or publish fanout

### Record

Owns:

- appending redaction-safe GWS audit records
- appending approval requests created by approval-gated GWS semantic actions
- publishing recorded artifacts to logs and later control-plane sinks

Does **not** own:

- session linkage
- semantic classification heuristics
- policy evaluation or approval decision logic
- recovering raw request payloads, email bodies, or document contents for storage or display

## Supported boundary labels in P6A-1

The boundary is intentionally small but explicit about the labels it will carry forward:

- signal sources:
  - `api_observation`
  - `network_observation`
- semantic surfaces:
  - `gws`
  - `gws.drive`
  - `gws.gmail`
  - `gws.admin`

These are boundary labels, not the final action taxonomy. Concrete actions such as `drive.permissions.update`, `drive.files.get_media`, `gmail.users.messages.send`, and `admin.reports.activities.list` are deferred to later tasks.

## Why this split now

This keeps the next tasks cleaner:

- **P6A-2** can implement minimal API / network action session linkage against a stable upstream seam
- **P6A-3** can add GWS semantic taxonomy without deciding how normalization or audit persistence work
- **P6A-5** can wire GWS policy evaluation against a stable evaluate seam
- **P6A-7** can reflect decisions and test audit behavior without reaching back into linkage or classification internals

## Explicitly out of scope for P6A-1

- concrete API instrumentation or network interception implementation details
- the minimal session-linkage implementation itself
- concrete GWS semantic action taxonomy rules
- concrete `agenta-core` GWS event normalization
- concrete `agenta-policy` evaluation
- durable audit / approval persistence implementation
- non-GWS SaaS coverage outside the initial scope
- full runbook / operator UX work

## Related docs

- architecture overview: [`overview.md`](overview.md)
- product requirements: [`../PRD.md`](../PRD.md)
- coverage matrix: [`coverage-matrix.md`](coverage-matrix.md)
- enforcement foundation: [`hostd-enforcement-foundation.md`](hostd-enforcement-foundation.md)
- secret-access boundary reference: [`hostd-secret-access-poc.md`](hostd-secret-access-poc.md)
