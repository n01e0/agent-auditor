# remote audit tamper-evident strategy

This note fixes the minimum tamper-evident design for the repository's remote durable audit path.

It builds on:

- [`remote-audit-integrity-boundary.md`](remote-audit-integrity-boundary.md)
- [`remote-audit-deployment-topology.md`](remote-audit-deployment-topology.md)
- [`observed-runtime-remote-ingress-contract.md`](observed-runtime-remote-ingress-contract.md)

The purpose of P19-4 is narrow:

- choose the baseline tamper-evident mechanism for the remote durable store
- define the minimum integrity metadata that must exist in durable audit records and store checkpoints
- keep the design aligned with the repository's checked-in `audit-records.jsonl` / `approval-requests.jsonl` vocabulary

This note does **not** choose the exact remote store engine, KMS/HSM product, external timestamping authority, or operator UI.

## decision

The checked-in baseline is:

> **per-stream hash chaining for every durable record, plus signed remote-store checkpoints for each stream head/segment**

In practice that means:

- every durable audit row is chained to the previous durable row in the same stream
- the remote durable store emits append-only signed checkpoints that anchor the current chain head and sealed segments
- investigator-facing verification depends on the remote-side chain + checkpoint history, not on any monitored-side spool copy

This intentionally chooses **hash chain first, signed checkpoint second**, instead of a per-record signature chain.

## why this is the baseline

This shape fits the repository better than a pure signature chain because it:

- preserves append order explicitly for JSONL streams
- keeps `audit-records.jsonl` and `approval-requests.jsonl` human-inspectable
- avoids putting remote signing-key operations on every single append
- makes log rotation and offline verification straightforward
- still gives third-party verifiability once the signed checkpoints are present

A per-record signature chain is still allowed as a stronger later variant, but it is **not** the minimum checked-in requirement.

## chain scope

The minimum chain scope is **one chain per durable stream**:

- `audit-records.jsonl`
- `approval-requests.jsonl`

Rules:

- the chain starts only after `remote hostd` accepts a record onto the remote durable path
- monitored-side local spool/debug copies are outside the authoritative chain
- rotation does **not** reset integrity history; the next segment continues from the last durable hash of the previous segment
- approval and audit streams stay separate; they may correlate by `event_id` / `approval_id`, but they do not share one mixed hash chain

## record-level integrity metadata

The remote durable store must carry a record-level integrity object on every durable row.

The field names should stay aligned with the existing `agenta-core` naming:

- `integrity.hash`
- `integrity.prev_hash`
- `integrity.signature`

### minimum required fields

#### `integrity.hash`

- required for every durable record
- the record's own hash in the durable stream
- encoded as an algorithm-prefixed string such as `sha256:<hex>`

#### `integrity.prev_hash`

- required except for the first durable row in a stream genesis segment
- points to the previous durable record hash in the same stream
- uses the same algorithm-prefixed encoding as `integrity.hash`

#### `integrity.signature`

- optional / reserved at the record level for the baseline design
- **not** required for normal remote durable-store appends
- may be used later for special export rows or stronger store engines, but investigators must not rely on it for the minimum checked-in path

## durable record coverage rule

For the two existing durable JSONL families, the minimum design is:

- `audit-records.jsonl`: keep storing `EventEnvelope`, with `EventEnvelope.integrity` populated on the remote durable path
- `approval-requests.jsonl`: add the same optional `integrity` object to durable approval rows so approvals can participate in the same verification model

The important rule is symmetry:

- both durable streams need chainable record metadata
- one stream must not become verifiable while the other remains an unchained blind spot

## canonical hashing rule

The record hash must be computed from a canonical payload representation so different serializers do not silently fork the chain.

Minimum rule:

1. take the durable record payload
2. omit the `integrity` object itself from the bytes being hashed
3. encode the remaining payload as canonical JSON UTF-8
4. hash the canonical payload together with the prior hash value for the same stream

A concrete implementation may define the byte framing later, but follow-on PRs should preserve these invariants:

- the same logical record yields the same canonical payload bytes
- changing record contents changes `integrity.hash`
- changing chain position changes `integrity.hash`
- recomputing a row requires knowledge of the prior durable row in the same stream

## store-level checkpoint metadata

Hash chaining alone is not enough; the remote durable store also needs signed checkpoints that freeze chain heads over time.

The minimum checked-in design is an append-only checkpoint log per durable stream, for example:

- `audit-records.integrity.jsonl`
- `approval-requests.integrity.jsonl`

Each checkpoint row should carry at least:

- `stream` — durable stream identity (`audit-records` / `approval-requests`)
- `checkpoint_kind` — `head` or `seal`
- `segment_id` — stable identifier for the current rotated file segment
- `record_count` — number of durable rows covered by this checkpoint in the segment
- `first_record_hash`
- `last_record_hash`
- `checkpointed_at`
- `prev_checkpoint_hash` — links checkpoint rows into their own append-only chain
- `checkpoint_hash` — hash of the checkpoint payload
- `signature` — signature over `checkpoint_hash`
- `signing_key_id` — identifies which remote audit signing key produced the signature

### checkpoint semantics

#### `head` checkpoints

These anchor the current open chain head on a bounded cadence.
They exist so the latest accepted remote rows do not remain unsigned until rotation.

#### `seal` checkpoints

These close a rotated or explicitly finalized segment.
They are the stable integrity anchor an investigator should expect to verify for archived segments.

## signature choice

The baseline remote checkpoint signature should be an asymmetric signature with stable key ids, for example `ed25519`.

The important repository-level rule is not the specific library but the shape:

- `signature` must be verifiable offline from exported checkpoint rows
- `signing_key_id` must let operators select the right public key after rotation
- signing keys live on the remote-audit ownership side, not on the monitored target side

## verification model

A third-party verifier should be able to:

1. read `audit-records.jsonl` or `approval-requests.jsonl`
2. recompute each row hash and verify the `prev_hash` chain
3. read the matching `*.integrity.jsonl` checkpoint log
4. verify the checkpoint chain (`prev_checkpoint_hash` -> `checkpoint_hash`)
5. verify the checkpoint signature using `signing_key_id`
6. confirm that the sealed or latest head checkpoint anchors the record chain they inspected

If that workflow is not possible, the implementation is still missing required tamper-evident metadata.

## relationship to local preview/spool state

This strategy applies only to the **remote durable store boundary**.

It does **not** mean:

- the monitored-side spool must be signed
- the same-host preview copy becomes final evidence
- local-volume inspection is enough to prove remote durable integrity

The monitored side may still keep retry/debug state, but the authoritative tamper-evident story begins only after remote acceptance and remote-side checkpointing.

## rejected baseline alternatives

### per-record signature chain as the only requirement

Rejected as the minimum because it makes every append depend on remote signing-key operations and does not buy enough extra value over a hash chain + signed checkpoints for the repository's JSONL-first design.

### hash chain without signed checkpoints

Rejected because an attacker with later write access to the remote store could rewrite the latest chain suffix and recompute hashes unless the remote side periodically signs chain heads.

### Merkle tree only, without append-order chaining

Rejected as the minimum because this phase needs an append-history story for investigator-facing JSONL logs, not just set-membership proofs.

## review questions for follow-on implementation PRs

Before merging a follow-on PR, reviewers should be able to answer:

1. where are `integrity.hash` and `integrity.prev_hash` written for both audit and approval durable rows?
2. where are the signed checkpoint rows persisted for each durable stream?
3. how does the implementation keep hot-chain head checkpoints from remaining unsigned indefinitely?
4. how does a verifier discover the public key for `signing_key_id`?
5. does the design keep monitored-side spool state explicitly outside the authoritative integrity chain?

If those answers are unclear, the PR is not yet implementing the checked-in tamper-evident strategy honestly.

## related docs

- remote audit integrity boundary: [`remote-audit-integrity-boundary.md`](remote-audit-integrity-boundary.md)
- remote audit deployment topology: [`remote-audit-deployment-topology.md`](remote-audit-deployment-topology.md)
- observed-runtime remote ingress contract: [`observed-runtime-remote-ingress-contract.md`](observed-runtime-remote-ingress-contract.md)
- architecture overview: [`overview.md`](overview.md)
- approval/control-plane audit export: [`approval-control-plane-audit-export.md`](approval-control-plane-audit-export.md)
