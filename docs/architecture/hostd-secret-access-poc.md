# hostd secret access MVP boundary

This note fixes the first internal split for the `agent-auditor-hostd` secret-access MVP.

## Goal of P4-1

Keep the first secret-access slice honest about ownership before taxonomy, normalized `agenta-core` secret events, policy wiring, and durable record storage land.

The immediate rule is:

- **classify** owns turning upstream filesystem-path and broker-request signals into redaction-safe secret-access candidates
- **evaluate** owns `agenta-core` normalization, `agenta-policy` bridging, and approval-gate projection
- **record** owns durable audit / approval persistence and publish fanout
- the shared seams are a small classify → evaluate contract and a small evaluate → record contract that both preserve the "no plaintext secret material crosses the seam" rule

Unlike the filesystem and network PoCs, there is no standalone **observe** stage here. Secret-access inputs are expected to arrive from existing upstream mechanisms (fanotify path access for secret files / mounted secrets, or explicit broker integration for brokered retrievals). P4-1 is only defining the secret-specific boundary after those upstream signals exist.

## Code layout

`cmd/agent-auditor-hostd/src/poc/secret/`

- `contract.rs`
  - shared seams between classify → evaluate and evaluate → record
  - supported upstream secret signal sources and redaction contract
- `classify.rs`
  - redaction-safe secret candidate classification plan
  - future home for secret taxonomy and mounted-secret / broker-request identification
- `evaluate.rs`
  - normalization + policy bridge plan after classification
  - current home for `agenta-core` secret event shaping from classified secret-access candidates
  - future home for `agenta-policy` secret evaluation
- `record.rs`
  - audit / approval record plan after evaluation
  - future home for append-only storage and publish fanout
- `mod.rs`
  - assembles the secret-access MVP plan and tests the split

## Responsibility split

### Classify

Owns:

- accepting path-like and broker-request secret signals from upstream collectors
- identifying `secret_file`, `mounted_secret`, and `brokered_secret_request` taxonomy kinds
- attaching redaction-safe locator hints, classifier labels, and rationale
- preserving enough source context for policy while dropping plaintext secret material
- handing off classified secret-access candidates downstream

Current P4-2 taxonomy notes:

- mounted secret paths win before generic secret-file heuristics so `/run/secrets/...` stays `mounted_secret` even if the basename looks like `.env`
- Kubernetes service-account token paths are a more specific mounted-secret subtype
- brokered secret requests are identified from broker-adapter input plus a redaction-safe locator hint, never from plaintext secret payloads

Does **not** own:

- `agenta-core` event normalization
- Rego / `agenta-policy` evaluation
- approval-request persistence or audit storage

### Evaluate

Owns:

- normalizing classified secret-access candidates toward `agenta-core`
- bridging those normalized candidates into `agenta-policy`
- projecting `allow` / `deny` / `require_approval` plus approval-request candidates for recording
- carrying the redaction contract forward into the record stage

Current P4-3 normalization notes:

- normalized events use `event_type=secret_access` and `action.class=secret`
- `action.target` carries only the redaction-safe locator hint, never plaintext secret material
- classifier metadata (`taxonomy_kind`, `taxonomy_variant`, labels, reasons, source kind) is preserved in action attributes for later policy and audit stages
- fanotify-derived secret access normalizes as a host-side collector event, while broker-adapter access normalizes as a control-plane sourced event

Current P4-4 policy notes:

- `agenta-policy` evaluates normalized secret events through a dedicated `examples/policies/secret_access.rego` bundle
- the current sample policy denies Kubernetes service-account mounted secret access
- the current sample policy requires approval for brokered secret retrievals and SSH secret-file access
- unmatched secret events fall back to the default allow path so taxonomy and normalization can stay testable before stricter policy arrives

Current P4-5 reflection notes:

- secret policy outcomes are reflected through the shared event-enrichment path, updating `result.status`, `result.reason`, and `policy.{decision,rule_id,severity,explanation}` on the normalized secret event
- the enriched secret `EventEnvelope` is treated as the audit-record shape for this stage, so audit consumers see the same allow / deny / require_approval outcome that the policy layer produced
- approval-gated secret outcomes also produce approval-request candidates, but append-only persistence remains deferred to P4-6

Does **not** own:

- upstream path / broker classification heuristics
- durable audit storage
- durable approval storage or publish fanout

### Record

Owns:

- appending redaction-safe secret audit records
- appending approval requests created by approval-gated secret access decisions
- publishing recorded artifacts to logs and later control-plane sinks

Does **not** own:

- source classification heuristics
- policy evaluation or approval decision logic
- recovering plaintext secret values for storage or display

## Why this split now

This keeps the next tasks cleaner:

- **P4-2** can implement secret taxonomy without mixing in policy or storage logic
- **P4-3** can shape classified secret candidates into `agenta-core` without owning classification heuristics
- **P4-4** can wire secret policy evaluation against a stable evaluate seam
- **P4-5 / P4-6** can reflect decisions and persist approval / audit records without reaching back into classification

## Explicitly out of scope for P4-1

- secret taxonomy rules beyond the boundary seam
- mounted secret / secret file / brokered request identification logic
- concrete `agenta-core` secret event normalization
- concrete `agenta-policy` secret evaluation
- durable audit / approval persistence implementation
- env var secret tracking

## Related docs

- product requirements: [`../PRD.md`](../PRD.md)
- coverage matrix: [`coverage-matrix.md`](coverage-matrix.md)
- roadmap: [`../roadmaps/secret-access-model-broker-mvp-tasklist.md`](../roadmaps/secret-access-model-broker-mvp-tasklist.md)
