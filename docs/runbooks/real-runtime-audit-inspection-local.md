# real-runtime audit inspection local runbook

This runbook fixes the **minimum local inspection path** for the P18 real-runtime handoff.

Use it when the question is:

> where did hostd write the observed-runtime request metadata, the reflected audit / approval records, and the local inspection view after OpenClaw or Hermes traffic hit the checked-in proxy seam?

This is an **inspection runbook** for the current dev/preview deployment assets. It does not by itself prove that a real runtime has already been exercised.

## what this path proves

Following this runbook lets an operator:

- locate the hostd-owned observed-runtime inbox created by the mitmproxy seam
- inspect the redaction-safe request envelopes written under the session runtime path
- locate the durable `audit-records.jsonl` / `approval-requests.jsonl` files under the hostd state dir
- use `agent-auditor-cli audit ...` to derive the checked-in local inspection view
- distinguish plain wiring success from stronger `observed_request` / `validated_observation` evidence

It does **not** prove:

- production-ready storage or dashboards
- full provider coverage for every possible OpenClaw or Hermes action
- inline live hold / deny enforcement
- that `fixture_preview`, `observed_request`, and `validated_observation` all apply to every record you inspect

## shared state-dir rule

In the checked-in Compose path, `hostd` runs with:

- state dir: `/state`

If you run hostd directly outside Compose, replace `/state` below with the path you passed to `--state-dir`.

## 1. keep the stack running long enough to inspect it

Use the same Compose stack you used for the real-runtime or stand-in traffic attempt.

Examples:

### topology A / forward proxy

```bash
docker compose \
  -f deploy/compose.yaml \
  -f deploy/compose.openclaw-forward-proxy.override.yaml \
  --env-file deploy/openclaw-forward-proxy.env \
  up hostd openclaw-forward-proxy openclaw-runtime-real
```

```bash
docker compose \
  -f deploy/compose.yaml \
  -f deploy/compose.hermes-forward-proxy.override.yaml \
  --env-file deploy/hermes-forward-proxy.env \
  up hostd hermes-forward-proxy hermes-runtime-real
```

### topology B / sidecar proxy

```bash
docker compose \
  -f deploy/compose.yaml \
  -f deploy/compose.openclaw-sidecar.override.yaml \
  --env-file deploy/openclaw-sidecar.env \
  --profile sidecar \
  up hostd openclaw-runtime-real-sidecar openclaw-proxy-real-sidecar
```

```bash
docker compose \
  -f deploy/compose.yaml \
  -f deploy/compose.hermes-sidecar.override.yaml \
  --env-file deploy/hermes-sidecar.env \
  --profile sidecar \
  up hostd hermes-runtime-real-sidecar hermes-proxy-real-sidecar
```

The inspection commands below assume `hostd` is still up and can see `/state`.

## 2. locate the observed-runtime session path

The proxy seam writes into the shared observed-runtime root:

```text
/state/agent-auditor-hostd-live-proxy-observed-runtime/
```

List the runtime sessions:

```bash
docker compose exec hostd find /state/agent-auditor-hostd-live-proxy-observed-runtime -maxdepth 3 -type f | sort
```

Expected shape:

```text
/state/agent-auditor-hostd-live-proxy-observed-runtime/sessions/<sanitized_session>__<sanitized_agent>__<sanitized_workspace>/metadata.json
/state/agent-auditor-hostd-live-proxy-observed-runtime/sessions/<sanitized_session>__<sanitized_agent>__<sanitized_workspace>/requests.jsonl
```

The directory name comes from the paired proxy env contract:

- `session_id`
- `agent_id`
- `workspace_id`

with non-alphanumeric characters sanitized to `_`.

## 3. inspect the observed-runtime envelope first

Start with `metadata.json` so you know you are looking at the right runtime lineage:

```bash
docker compose exec hostd bash -lc '
  for file in /state/agent-auditor-hostd-live-proxy-observed-runtime/sessions/*/metadata.json; do
    echo "== $file =="
    jq . "$file"
  done
'
```

Then inspect the redaction-safe request envelopes:

```bash
docker compose exec hostd bash -lc '
  for file in /state/agent-auditor-hostd-live-proxy-observed-runtime/sessions/*/requests.jsonl; do
    echo "== $file =="
    jq -c "{
      source,
      request_id,
      correlation_id,
      session_id,
      agent_id,
      workspace_id,
      provider_hint,
      transport,
      method,
      authority,
      path,
      target_hint,
      mode,
      content_retained
    }" "$file"
  done
'
```

Read that output as the **proxy-to-hostd ingress proof** only.

What you want to see here:

- `source="forward_proxy"`
- the expected `session_id` / `agent_id` / `workspace_id`
- provider-specific host/path hints such as:
  - `authority="api.github.com"`
  - `authority="gmail.googleapis.com"`
- `content_retained=false`

If `requests.jsonl` is empty or missing, stop there: you do not yet have a hostd-observed runtime request to inspect further.

## 4. locate the durable audit / approval store

Hostd persists reflected records under store directories in the same state dir.

List them with:

```bash
docker compose exec hostd find /state -maxdepth 1 -type d -name 'agent-auditor-hostd*-store' | sort
```

Current examples you may see for the real-runtime handoff path:

- `/state/agent-auditor-hostd-github-poc-store`
- `/state/agent-auditor-hostd-gws-poc-store`
- other checked-in PoC stores if the bootstrap examples also ran in the same state dir

Then inspect the actual files:

```bash
docker compose exec hostd find /state -maxdepth 2 \( -name 'audit-records.jsonl' -o -name 'approval-requests.jsonl' \) | sort
```

## 5. inspect raw audit / approval JSONL

### audit records

```bash
docker compose exec hostd jq -c '{
  event_id,
  event_type,
  result_status: .result.status,
  action_verb: .action.verb,
  target: .action.target,
  source_kind: .action.attributes.source_kind,
  live_request_source_kind: .action.attributes.live_request_source_kind,
  observation_provenance: .action.attributes.observation_provenance,
  validation_status: .action.attributes.validation_status,
  session_correlation_status: .action.attributes.session_correlation_status
}' /state/agent-auditor-hostd-github-poc-store/audit-records.jsonl
```

### approval requests

```bash
docker compose exec hostd jq -c '{
  approval_id,
  event_id,
  status,
  action_verb: .request.action_verb,
  target: .request.target,
  source_kind: .request.attributes.source_kind,
  observation_provenance: .request.attributes.observation_provenance,
  validation_status: .request.attributes.validation_status,
  session_correlation_status: .request.attributes.session_correlation_status
}' /state/agent-auditor-hostd-gws-poc-store/approval-requests.jsonl
```

Use the store that matches the provider/action you are actually inspecting.

Typical reading rule:

- `source_kind=live_proxy_observed` means the record came from the proxy envelope layer
- `source_kind=api_observation` means the provider-specific normalization/classification layer ran
- `session_correlation_status=runtime_path_confirmed` means hostd linked the provider-level record back to the observed-runtime path

## 6. derive the checked-in local inspection view with the CLI

For reviewer-facing inspection, use `agent-auditor-cli audit ...` against the same state dir.

### list the available durable records

```bash
docker compose exec hostd bash -lc 'cargo run -p agent-auditor-cli -- audit list --state-dir /state | sed -n "1,40p"'
```

### tail only approvals or only audit rows

```bash
docker compose exec hostd bash -lc 'cargo run -p agent-auditor-cli -- audit tail --state-dir /state --kind approval --count 10'
```

```bash
docker compose exec hostd bash -lc 'cargo run -p agent-auditor-cli -- audit tail --state-dir /state --kind audit --count 10'
```

### show one record with local inspection fields expanded

```bash
docker compose exec hostd bash -lc 'cargo run -p agent-auditor-cli -- audit show --state-dir /state <event_id_or_approval_id>'
```

Expected shape:

- for approval rows:
  - `record`
  - `local_inspection`
  - `observation_local_inspection`
- for audit rows:
  - `record`
  - `observation_local_inspection`

The most important fields for the P18 handoff are inside `observation_local_inspection`:

- `observation_provenance`
- `validation_status`
- `evidence_tier`
- `capture_source`
- `session_correlation_status`

## 7. how to read the evidence correctly

Use this rule when deciding what the inspected files actually prove.

### only wiring success

You have only wiring success when you can show:

- `metadata.json` and `requests.jsonl` exist under the observed-runtime session path
- the request envelope has the expected lineage and target hints

That proves the proxy seam wrote into hostd's observed-runtime inbox.
It does **not** yet prove provider normalization or stronger evidence tiering.

### observed request

You have an **observed request** when the provider-level record or its local inspection shows:

- `observation_provenance="observed_request"`

This is stronger than fixture preview, but not yet the same thing as a validated observation.

### validated observation

You have a **validated observation** only when the local inspection or persisted record also shows:

- `validation_status="validated_observation"`
- `evidence_tier="validated_observation"`

At the current checked-in boundary, that tier is intentionally narrow and route-specific.
Do not generalize one validated path into a blanket claim that all OpenClaw or Hermes traffic is now validated.

### still fixture preview

If the local inspection says:

- `observation_provenance="fixture_preview"`
- `validation_status="fixture_preview"`

then you are still looking at the repository's checked-in preview/bootstrap evidence, not a real observed runtime request.

## 8. quick troubleshooting branches

### `requests.jsonl` exists, but no audit / approval record appears

Check:

- whether the provider/action is one of the currently classified checked-in paths
- whether hostd logs show normalization/policy errors
- whether you are looking in the right store directory under `/state`

### audit / approval files exist, but `session_correlation_status` is missing

Treat that as a correlation failure between the provider-level record and the observed-runtime path.
Do not upgrade the evidence claim until that field is present and correct.

### CLI `audit list` is empty

Check:

- that you passed the same `--state-dir` hostd is using
- that `audit-records.jsonl` / `approval-requests.jsonl` actually exist under `/state`
- that the real runtime generated traffic after the current state dir was initialized

## related docs

- deploy entrypoint: [`../../deploy/README.md`](../../deploy/README.md)
- real-runtime readiness boundary: [`../architecture/real-runtime-audit-readiness-boundary.md`](../architecture/real-runtime-audit-readiness-boundary.md)
- real-traffic evidence boundary: [`../architecture/real-traffic-observation-boundary.md`](../architecture/real-traffic-observation-boundary.md)
- approval JSONL inspection: [`approval-jsonl-inspection-local.md`](approval-jsonl-inspection-local.md)
- GitHub slice example: [`hostd-github-semantic-governance-poc-local.md`](hostd-github-semantic-governance-poc-local.md)
