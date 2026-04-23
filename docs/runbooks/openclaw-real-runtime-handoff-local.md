# OpenClaw real-runtime handoff local runbook

This runbook fixes the **human handoff path** for `n01e0` to run one real OpenClaw verification through the checked-in proxy seam and collect the minimum honest evidence.

Use it when the question is:

> what exactly should I run for OpenClaw, what evidence should I expect, and how do I tell wiring success from a stronger observed or validated result?

This is a **handoff runbook**. It prepares and checks one OpenClaw real-runtime exercise, but it does not claim that the repository has already produced that evidence.

## target of this handoff

The current OpenClaw handoff is intentionally narrow.

The preferred first exercise is:

- one real OpenClaw container
- routed through topology **A / forward proxy** or **B / sidecar proxy**
- making one intentional GitHub repository-visibility update against a disposable repo you control
- producing the checked-in GitHub `repos.update_visibility` path that already has the narrowest validated-observation contract in the repository

Why this route first:

- the live proxy seam already has a documented observed-runtime path
- the GitHub slice already has the clearest checked-in `validated_observation` contract
- the expected evidence is concrete enough to verify without guessing hidden joins

## before you start

Complete these first:

1. real image wiring for the topology you want:
   - topology A: [`../../deploy/compose.openclaw-forward-proxy.override.yaml`](../../deploy/compose.openclaw-forward-proxy.override.yaml)
   - topology B: [`../../deploy/compose.openclaw-sidecar.override.yaml`](../../deploy/compose.openclaw-sidecar.override.yaml)
2. dev CA / trust bootstrap:
   - [`real-runtime-proxy-trust-bootstrap-dev.md`](real-runtime-proxy-trust-bootstrap-dev.md)
3. inspection path overview:
   - [`real-runtime-audit-inspection-local.md`](real-runtime-audit-inspection-local.md)

You also need:

- a disposable GitHub repo you are willing to let OpenClaw modify
- the repo owner/name available up front
- a real OpenClaw image with whatever credentials/config it needs to reach GitHub
- the confidence that setting the repo visibility is acceptable for this test

## safety boundary for the verification target

Use a throwaway or otherwise explicitly safe repo.

This handoff is about proving the audit path, not about safely changing a meaningful production repo.
If you cannot tolerate the repo becoming public or private during the test, pick a different repo.

The least surprising path is usually:

- choose a disposable repo
- ask OpenClaw to set its visibility to **private**
- treat any later revert as a separate manual cleanup step

If OpenClaw emits the PATCH request but the repo was already private, that can still be enough for the audit evidence as long as the request actually crossed the proxy seam.

## 1. pick one topology and copy the matching env files

### topology A / forward proxy

```bash
cp deploy/openclaw-forward-proxy.env.sample deploy/openclaw-forward-proxy.env
cp deploy/openclaw-forward-proxy.runtime.env.sample deploy/openclaw-forward-proxy.runtime.env
```

Edit at least:

- `OPENCLAW_RUNTIME_IMAGE`
- `OPENCLAW_RUNTIME_ENV_FILE` if you renamed the runtime env file
- the real OpenClaw runtime credentials/config in `deploy/openclaw-forward-proxy.runtime.env`

### topology B / sidecar proxy

```bash
cp deploy/openclaw-sidecar.env.sample deploy/openclaw-sidecar.env
cp deploy/openclaw-sidecar.runtime.env.sample deploy/openclaw-sidecar.runtime.env
```

Edit at least:

- `OPENCLAW_SIDECAR_RUNTIME_IMAGE`
- `OPENCLAW_SIDECAR_RUNTIME_ENV_FILE` if you renamed the runtime env file
- the real OpenClaw runtime credentials/config in `deploy/openclaw-sidecar.runtime.env`

## 2. render the exact config before you run it

### topology A / forward proxy

```bash
docker compose \
  -f deploy/compose.yaml \
  -f deploy/compose.openclaw-forward-proxy.override.yaml \
  --env-file deploy/openclaw-forward-proxy.env \
  config
```

### topology B / sidecar proxy

```bash
docker compose \
  -f deploy/compose.yaml \
  -f deploy/compose.openclaw-sidecar.override.yaml \
  --env-file deploy/openclaw-sidecar.env \
  --profile sidecar \
  config
```

Do not skip this. If config rendering already fails, the later runtime result is not trustworthy.

## 3. make sure the trust bootstrap is really done

You should already have the matching OpenClaw CA exported from the trust-bootstrap runbook:

```bash
ls -l deploy/local/mitmproxy-ca/openclaw/mitmproxy-ca-cert.pem
openssl x509 -in deploy/local/mitmproxy-ca/openclaw/mitmproxy-ca-cert.pem -noout -subject -issuer -dates
```

And your real OpenClaw image should already trust that CA either:

- via the OS trust store in a derived image, or
- via runtime env such as `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`, or `SSL_CERT_FILE`

If this step is still uncertain, stop and finish [`real-runtime-proxy-trust-bootstrap-dev.md`](real-runtime-proxy-trust-bootstrap-dev.md) first.

## 4. start the stack

### topology A / forward proxy

```bash
docker compose \
  -f deploy/compose.yaml \
  -f deploy/compose.openclaw-forward-proxy.override.yaml \
  --env-file deploy/openclaw-forward-proxy.env \
  up -d hostd openclaw-forward-proxy openclaw-runtime-real
```

### topology B / sidecar proxy

```bash
docker compose \
  -f deploy/compose.yaml \
  -f deploy/compose.openclaw-sidecar.override.yaml \
  --env-file deploy/openclaw-sidecar.env \
  --profile sidecar \
  up -d hostd openclaw-runtime-real-sidecar openclaw-proxy-real-sidecar
```

Quick sanity check:

### topology A

```bash
docker compose \
  -f deploy/compose.yaml \
  -f deploy/compose.openclaw-forward-proxy.override.yaml \
  --env-file deploy/openclaw-forward-proxy.env \
  ps
```

### topology B

```bash
docker compose \
  -f deploy/compose.yaml \
  -f deploy/compose.openclaw-sidecar.override.yaml \
  --env-file deploy/openclaw-sidecar.env \
  --profile sidecar \
  ps
```

You want all three relevant services healthy/running for the chosen topology:

- `hostd`
- the paired OpenClaw proxy service
- the real OpenClaw runtime service

## 5. trigger the OpenClaw action on purpose

Inside the real OpenClaw runtime, trigger one GitHub repo-visibility change against the disposable repo.

The exact in-runtime prompt is OpenClaw-specific, but the intent must be explicit enough that the resulting GitHub request is a repository visibility update.

Use an instruction equivalent to:

> Make the GitHub repository `<owner>/<repo>` private.

The important part is not the exact wording. The important part is that OpenClaw emits a real GitHub API request that maps to:

- semantic action: `repos.update_visibility`
- authority: `api.github.com`
- target hint: `repos/<owner>/<repo>/visibility`

## 6. first confirm that the proxy seam actually saw the request

### topology A

```bash
docker compose \
  -f deploy/compose.yaml \
  -f deploy/compose.openclaw-forward-proxy.override.yaml \
  --env-file deploy/openclaw-forward-proxy.env \
  logs --tail=200 openclaw-forward-proxy hostd
```

### topology B

```bash
docker compose \
  -f deploy/compose.yaml \
  -f deploy/compose.openclaw-sidecar.override.yaml \
  --env-file deploy/openclaw-sidecar.env \
  --profile sidecar \
  logs --tail=200 openclaw-proxy-real-sidecar hostd
```

Then inspect the observed-runtime request envelope:

```bash
docker compose exec hostd bash -lc '
  for file in /state/agent-auditor-hostd-live-proxy-observed-runtime/sessions/*/requests.jsonl; do
    echo "== $file =="
    jq -c "select(.authority == \"api.github.com\") | {
      request_id,
      correlation_id,
      session_id,
      agent_id,
      workspace_id,
      authority,
      method,
      path,
      target_hint,
      mode,
      content_retained
    }" "$file"
  done
'
```

Minimum expected wiring evidence:

- `authority="api.github.com"`
- `method="patch"`
- `target_hint="repos/<owner>/<repo>/visibility"`
- the expected OpenClaw `session_id` / `agent_id` / `workspace_id`
- `content_retained=false`

If you only have this step, you have **wiring success** and likely at least ingress capture, but you do **not** yet have the stronger validated proof.

## 7. confirm the durable audit / approval artifacts

Inspect the GitHub store directly:

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
  validation_capture_source: .action.attributes.validation_capture_source,
  session_correlation_status: .action.attributes.session_correlation_status
}' /state/agent-auditor-hostd-github-poc-store/audit-records.jsonl
```

```bash
docker compose exec hostd jq -c '{
  approval_id,
  event_id,
  status,
  action_verb: .request.action_verb,
  target: .request.target,
  observation_provenance: .request.attributes.observation_provenance,
  validation_status: .request.attributes.validation_status,
  session_correlation_status: .request.attributes.session_correlation_status
}' /state/agent-auditor-hostd-github-poc-store/approval-requests.jsonl
```

Minimum expected OpenClaw/GitHub record evidence:

- audit record:
  - `event_type="github_action"`
  - `action_verb="repos.update_visibility"`
  - `source_kind="api_observation"`
  - `live_request_source_kind="live_proxy_observed"`
  - `observation_provenance="observed_request"`
  - `validation_status="validated_observation"`
  - `validation_capture_source="forward_proxy_observed_runtime_path"`
  - `session_correlation_status="runtime_path_confirmed"`
- approval request:
  - `action_verb="repos.update_visibility"`
  - `observation_provenance="observed_request"`
  - `validation_status="validated_observation"`
  - `session_correlation_status="runtime_path_confirmed"`

## 8. confirm the checked-in local inspection view

List the newest durable rows:

```bash
docker compose exec hostd bash -lc 'cargo run -p agent-auditor-cli -- audit tail --state-dir /state --kind all --count 20'
```

Pick the relevant `event_id` or `approval_id`, then show it in full:

```bash
docker compose exec hostd bash -lc 'cargo run -p agent-auditor-cli -- audit show --state-dir /state <event_id_or_approval_id>'
```

The strongest expected inspection evidence is inside `observation_local_inspection`:

- `observation_provenance="observed_request"`
- `validation_status="validated_observation"`
- `evidence_tier="validated_observation"`
- `capture_source="forward_proxy_observed_runtime_path"`
- `session_correlation_status="runtime_path_confirmed"`

If those fields are present, you have the repository's current strongest honest claim for this OpenClaw exercise.

## minimum evidence bundle to save

For the OpenClaw handoff, save at least these artifacts:

1. the rendered compose config command you actually used
2. one observed-runtime `requests.jsonl` line showing the GitHub request envelope
3. one GitHub `audit-records.jsonl` line showing `repos.update_visibility`
4. one GitHub `approval-requests.jsonl` line for the same action
5. one `agent-auditor-cli audit show --state-dir /state ...` output showing `observation_local_inspection`
6. the exact image tag and topology you used

That bundle is enough for someone else to judge whether the result stopped at wiring success, reached `observed_request`, or reached `validated_observation`.

## how to read the outcome honestly

### outcome A: only wiring success

You saw:

- the proxy envelope under `requests.jsonl`

But you did **not** see:

- a GitHub audit/approval record with `observed_request` / `validated_observation`

That means the proxy seam saw traffic, but the provider-level validated path was not completed.

### outcome B: observed request only

You saw:

- `observation_provenance="observed_request"`

But not:

- `validation_status="validated_observation"`
- `evidence_tier="validated_observation"`

That means real traffic was captured, but the narrower validated contract was not completed.

### outcome C: validated observation

You saw all of:

- `observation_provenance="observed_request"`
- `validation_status="validated_observation"`
- `evidence_tier="validated_observation"`
- `session_correlation_status="runtime_path_confirmed"`

That is the current strongest honest result for the OpenClaw handoff.
It still does **not** mean broad OpenClaw coverage or fail-closed enforcement is done.

## quick troubleshooting branches

### OpenClaw logs show TLS or certificate failures

Look for errors like:

- `certificate verify failed`
- `self signed certificate`
- `unable to get local issuer certificate`

If you see those, go back to [`real-runtime-proxy-trust-bootstrap-dev.md`](real-runtime-proxy-trust-bootstrap-dev.md).
Do not keep retrying the runtime action until the trust path is fixed.

### no GitHub request appears in `requests.jsonl`

Check the runtime env inside the container.

### topology A

```bash
docker compose \
  -f deploy/compose.yaml \
  -f deploy/compose.openclaw-forward-proxy.override.yaml \
  --env-file deploy/openclaw-forward-proxy.env \
  exec openclaw-runtime-real env | grep -E 'HTTP_PROXY|HTTPS_PROXY|NO_PROXY'
```

### topology B

```bash
docker compose \
  -f deploy/compose.yaml \
  -f deploy/compose.openclaw-sidecar.override.yaml \
  --env-file deploy/openclaw-sidecar.env \
  --profile sidecar \
  exec openclaw-runtime-real-sidecar env | grep -E 'HTTP_PROXY|HTTPS_PROXY|NO_PROXY'
```

If those proxy vars are missing or wrong, the runtime is not actually routed through mitmproxy.

### a GitHub request exists, but the path is not `repos.update_visibility`

That means the manual OpenClaw exercise hit a different GitHub route.
For this handoff, retry with a narrower instruction that explicitly asks OpenClaw to change repo visibility on the disposable repo.

### audit records exist, but they still show `fixture_preview`

That means you are looking at bootstrap preview data instead of the real request path.
Cross-check:

- the newest timestamps
- the `session_id` / `agent_id`
- the GitHub target repo
- whether the real runtime actually sent traffic after the current stack started

### audit record exists, but `session_correlation_status` is not `runtime_path_confirmed`

Treat that as a correlation failure.
Do not upgrade the result beyond observed ingress until the session/runtime linkage is correct.

## cleanup after the exercise

When you are done:

### topology A

```bash
docker compose \
  -f deploy/compose.yaml \
  -f deploy/compose.openclaw-forward-proxy.override.yaml \
  --env-file deploy/openclaw-forward-proxy.env \
  down
```

### topology B

```bash
docker compose \
  -f deploy/compose.yaml \
  -f deploy/compose.openclaw-sidecar.override.yaml \
  --env-file deploy/openclaw-sidecar.env \
  --profile sidecar \
  down
```

If you changed the repo visibility as part of the test, revert it separately and deliberately.
Do not hide that revert inside the evidence narrative.

## related docs

- deploy entrypoint: [`../../deploy/README.md`](../../deploy/README.md)
- proxy trust bootstrap: [`real-runtime-proxy-trust-bootstrap-dev.md`](real-runtime-proxy-trust-bootstrap-dev.md)
- audit inspection path: [`real-runtime-audit-inspection-local.md`](real-runtime-audit-inspection-local.md)
- real-runtime readiness boundary: [`../architecture/real-runtime-audit-readiness-boundary.md`](../architecture/real-runtime-audit-readiness-boundary.md)
- real-traffic evidence boundary: [`../architecture/real-traffic-observation-boundary.md`](../architecture/real-traffic-observation-boundary.md)
- GitHub validated-observation slice example: [`hostd-github-semantic-governance-poc-local.md`](hostd-github-semantic-governance-poc-local.md)
