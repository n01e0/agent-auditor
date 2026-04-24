# Hermes real-runtime handoff local runbook

This runbook fixes the **human handoff path** for `n01e0` to run one real Hermes verification through the checked-in proxy seam and collect the minimum honest evidence.

Use it when the question is:

> what exactly should I run for Hermes, what evidence should I expect, and how do I tell wiring success from the strongest Hermes result the repository currently supports?

This is a **handoff runbook**. It prepares and checks one Hermes real-runtime exercise, but it does not claim that the repository has already produced that evidence.

## target of this handoff

The current Hermes handoff is intentionally narrow.

The preferred first exercise is:

- one real Hermes container
- routed through topology **A / forward proxy** or **B / sidecar proxy**
- making one intentional Gmail send against a test inbox you control
- producing the checked-in GWS `gmail.users.messages.send` path that already has the narrowest Hermes-adjacent `observed_request` contract in the repository

Why this route first:

- the live proxy seam already has a documented observed-runtime path
- the GWS slice already has a checked-in `observed_request` example for Gmail send
- the expected evidence is concrete enough to inspect without guessing hidden joins

Important boundary:

- the current Hermes/GWS path stops at **`observed_request`**
- unlike the GitHub/OpenClaw handoff, this Hermes path does **not** currently have a checked-in `validated_observation` contract

## before you start

Complete these first:

1. real image wiring for the topology you want:
   - topology A: [`../../deploy/compose.hermes-forward-proxy.override.yaml`](../../deploy/compose.hermes-forward-proxy.override.yaml)
   - topology B: [`../../deploy/compose.hermes-sidecar.override.yaml`](../../deploy/compose.hermes-sidecar.override.yaml)
2. dev CA / trust bootstrap:
   - [`real-runtime-proxy-trust-bootstrap-dev.md`](real-runtime-proxy-trust-bootstrap-dev.md)
3. inspection path overview:
   - [`real-runtime-audit-inspection-local.md`](real-runtime-audit-inspection-local.md)

You also need:

- one test inbox you control and are willing to receive a Hermes-generated message at
- a real Hermes image with whatever credentials/config it needs to call Gmail
- the confidence that sending one test email is acceptable for this check

## safety boundary for the verification target

Use a test inbox you control.

This handoff is about proving the audit path, not about testing broad Hermes behavior against real people.
If you cannot tolerate one test message landing in the target inbox, pick a different inbox.

The least surprising path is usually:

- choose a dedicated test address
- send one short clearly labeled message
- treat any cleanup, deletion, or inbox housekeeping as a separate manual step

## 1. pick one topology and copy the matching env files

### topology A / forward proxy

```bash
cp deploy/hermes-forward-proxy.env.sample deploy/hermes-forward-proxy.env
cp deploy/hermes-forward-proxy.runtime.env.sample deploy/hermes-forward-proxy.runtime.env
```

Edit at least:

- `HERMES_RUNTIME_IMAGE`
- `HERMES_RUNTIME_ENV_FILE` if you renamed the runtime env file
- the real Hermes runtime credentials/config in `deploy/hermes-forward-proxy.runtime.env`
- if the Hermes launcher or bundled tools need explicit runtime env wiring, mirror the checked-in proxy/cert contract there too:
  - `http_proxy=http://hermes-forward-proxy:8080`
  - `https_proxy=http://hermes-forward-proxy:8080`
  - `no_proxy=hostd,localhost,127.0.0.1`
  - `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`, `SSL_CERT_FILE`, `CURL_CA_BUNDLE`, and `GIT_SSL_CAINFO` pointed at `/opt/agent-auditor/certs/mitmproxy-ca-cert.pem` as needed by the image

### topology B / sidecar proxy

```bash
cp deploy/hermes-sidecar.env.sample deploy/hermes-sidecar.env
cp deploy/hermes-sidecar.runtime.env.sample deploy/hermes-sidecar.runtime.env
```

Edit at least:

- `HERMES_SIDECAR_RUNTIME_IMAGE`
- `HERMES_SIDECAR_RUNTIME_ENV_FILE` if you renamed the runtime env file
- the real Hermes runtime credentials/config in `deploy/hermes-sidecar.runtime.env`
- if the Hermes launcher or bundled tools need explicit runtime env wiring, mirror the checked-in sidecar proxy/cert contract there too:
  - `http_proxy=http://127.0.0.1:8080`
  - `https_proxy=http://127.0.0.1:8080`
  - `no_proxy=hostd,localhost,127.0.0.1`
  - `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`, `SSL_CERT_FILE`, `CURL_CA_BUNDLE`, and `GIT_SSL_CAINFO` pointed at `/opt/agent-auditor/certs/mitmproxy-ca-cert.pem` as needed by the image

## 2. render the exact config before you run it

### topology A / forward proxy

```bash
docker compose \
  -f deploy/compose.yaml \
  -f deploy/compose.hermes-forward-proxy.override.yaml \
  --env-file deploy/hermes-forward-proxy.env \
  config
```

### topology B / sidecar proxy

```bash
docker compose \
  -f deploy/compose.yaml \
  -f deploy/compose.hermes-sidecar.override.yaml \
  --env-file deploy/hermes-sidecar.env \
  --profile sidecar \
  config
```

Do not skip this. If config rendering already fails, the later runtime result is not trustworthy.

## 3. make sure the trust bootstrap is really done

You should already have the matching Hermes CA exported from the trust-bootstrap runbook:

```bash
ls -l deploy/local/mitmproxy-ca/hermes/mitmproxy-ca-cert.pem
openssl x509 -in deploy/local/mitmproxy-ca/hermes/mitmproxy-ca-cert.pem -noout -subject -issuer -dates
```

And your real Hermes image should already trust that CA either:

- via the OS trust store in a derived image, or
- via runtime env such as `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`, `SSL_CERT_FILE`, `CURL_CA_BUNDLE`, or `GIT_SSL_CAINFO` pointed at `/opt/agent-auditor/certs/mitmproxy-ca-cert.pem`

If this step is still uncertain, stop and finish [`real-runtime-proxy-trust-bootstrap-dev.md`](real-runtime-proxy-trust-bootstrap-dev.md) first.

## 4. start the stack

### topology A / forward proxy

```bash
docker compose \
  -f deploy/compose.yaml \
  -f deploy/compose.hermes-forward-proxy.override.yaml \
  --env-file deploy/hermes-forward-proxy.env \
  up -d hostd hermes-forward-proxy hermes-runtime-real
```

### topology B / sidecar proxy

```bash
docker compose \
  -f deploy/compose.yaml \
  -f deploy/compose.hermes-sidecar.override.yaml \
  --env-file deploy/hermes-sidecar.env \
  --profile sidecar \
  up -d hostd hermes-runtime-real-sidecar hermes-proxy-real-sidecar
```

Quick sanity check:

### topology A

```bash
docker compose \
  -f deploy/compose.yaml \
  -f deploy/compose.hermes-forward-proxy.override.yaml \
  --env-file deploy/hermes-forward-proxy.env \
  ps
```

### topology B

```bash
docker compose \
  -f deploy/compose.yaml \
  -f deploy/compose.hermes-sidecar.override.yaml \
  --env-file deploy/hermes-sidecar.env \
  --profile sidecar \
  ps
```

You want all three relevant services healthy/running for the chosen topology:

- `hostd`
- the paired Hermes proxy service
- the real Hermes runtime service

## 5. trigger the Hermes action on purpose

Inside the real Hermes runtime, trigger one Gmail send to the test inbox you control.

The exact in-runtime prompt is Hermes-specific, but the intent must be explicit enough that the resulting Google API request is a Gmail send.

Use an instruction equivalent to:

> Send a short test email to `<test-address>` with subject `agent-auditor Hermes proxy test`.

The important part is not the exact wording. The important part is that Hermes emits a real Gmail API request that maps to:

- semantic action: `gmail.users.messages.send`
- authority: `gmail.googleapis.com`
- target hint: `gmail.users/me`

## 6. first confirm that the proxy seam actually saw the request

### topology A

```bash
docker compose \
  -f deploy/compose.yaml \
  -f deploy/compose.hermes-forward-proxy.override.yaml \
  --env-file deploy/hermes-forward-proxy.env \
  logs --tail=200 hermes-forward-proxy hostd
```

### topology B

```bash
docker compose \
  -f deploy/compose.yaml \
  -f deploy/compose.hermes-sidecar.override.yaml \
  --env-file deploy/hermes-sidecar.env \
  --profile sidecar \
  logs --tail=200 hermes-proxy-real-sidecar hostd
```

Then inspect the observed-runtime request envelope:

```bash
docker compose exec hostd bash -lc '
  for file in /state/agent-auditor-hostd-live-proxy-observed-runtime/sessions/*/requests.jsonl; do
    echo "== $file =="
    jq -c "select(.authority == \"gmail.googleapis.com\") | {
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

- `authority="gmail.googleapis.com"`
- `method="post"`
- `path="/gmail/v1/users/me/messages/send"`
- `target_hint="gmail.users/me"`
- the expected Hermes `session_id` / `agent_id` / `workspace_id`
- `content_retained=false`

If you only have this step, you have **wiring success** and likely at least ingress capture, but you do **not** yet have the stronger durable Hermes result.

## 7. confirm the durable audit / approval artifacts

Inspect the GWS store directly:

```bash
docker compose exec hostd jq -c '{
  event_id,
  event_type,
  result_status: .result.status,
  action_verb: .action.verb,
  target: .action.target,
  source_kind: .action.attributes.source_kind,
  observation_provenance: .action.attributes.observation_provenance,
  validation_status: .action.attributes.validation_status,
  session_correlation_status: .action.attributes.session_correlation_status,
  mode_status: .action.attributes.mode_status,
  record_status: .action.attributes.record_status,
  redaction_status: .action.attributes.redaction_status
}' /state/agent-auditor-hostd-gws-poc-store/audit-records.jsonl
```

```bash
docker compose exec hostd jq -c '{
  approval_id,
  event_id,
  status,
  enforcement_status: .enforcement.status,
  action_verb: .request.action_verb,
  target: .request.target,
  observation_provenance: .request.attributes.observation_provenance,
  validation_status: .request.attributes.validation_status,
  session_correlation_status: .request.attributes.session_correlation_status
}' /state/agent-auditor-hostd-gws-poc-store/approval-requests.jsonl
```

Minimum expected Hermes/GWS record evidence:

- audit record:
  - `event_type="gws_action"`
  - `action_verb="gmail.users.messages.send"`
  - `source_kind="live_proxy_observed"`
  - `observation_provenance="observed_request"`
  - `validation_status="observed_request"`
  - `session_correlation_status="runtime_path_confirmed"`
  - `mode_status="enforce_preview_record_only"`
  - `record_status="enforce_preview_approval_request_recorded"`
  - `redaction_status="redaction_safe_preview_only"`
- approval request:
  - `action_verb="gmail.users.messages.send"`
  - `observation_provenance="observed_request"`
  - `validation_status="observed_request"`
  - `session_correlation_status="runtime_path_confirmed"`
  - `enforcement_status="observe_only_fallback"`

This is still a fail-open, preview-only approval path. The real request was observed and reflected into durable records, but it was not paused inline.

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
- `validation_status="observed_request"`
- `evidence_tier="observed_request"`
- `session_correlation_status="runtime_path_confirmed"`

If those fields are present, you have the repository's current strongest honest claim for this Hermes exercise.

## minimum evidence bundle to save

For the Hermes handoff, save at least these artifacts:

1. the rendered compose config command you actually used
2. one observed-runtime `requests.jsonl` line showing the Gmail request envelope
3. one GWS `audit-records.jsonl` line showing `gmail.users.messages.send`
4. one GWS `approval-requests.jsonl` line for the same action
5. one `agent-auditor-cli audit show --state-dir /state ...` output showing `observation_local_inspection`
6. the exact image tag, topology, and test inbox you used

That bundle is enough for someone else to judge whether the result stopped at wiring success or reached the current Hermes `observed_request` tier.

## how to read the outcome honestly

### outcome A: only wiring success

You saw:

- the proxy envelope under `requests.jsonl`

But you did **not** see:

- a durable GWS audit/approval record with `observed_request`

That means the proxy seam saw traffic, but the provider-level durable path was not completed.

### outcome B: observed request

You saw all of:

- `observation_provenance="observed_request"`
- `validation_status="observed_request"`
- `evidence_tier="observed_request"`
- `session_correlation_status="runtime_path_confirmed"`

That is the current strongest honest result for the Hermes handoff.
It still does **not** mean broad Hermes coverage or fail-closed enforcement is done.

### there is no checked-in Hermes validated-observation outcome yet

Do **not** upgrade this Hermes/GWS exercise to `validated_observation` just because the repository has one validated GitHub path elsewhere.
The GitHub/OpenClaw handoff and the Hermes/GWS handoff currently stop at different evidence tiers.

## quick troubleshooting branches

### Hermes logs show TLS or certificate failures

Look for errors like:

- `certificate verify failed`
- `self signed certificate`
- `unable to get local issuer certificate`

If you see those, go back to [`real-runtime-proxy-trust-bootstrap-dev.md`](real-runtime-proxy-trust-bootstrap-dev.md).
Do not keep retrying the runtime action until the trust path is fixed.

If Hermes itself can reach Gmail but a bundled helper still fails during bootstrap, compare the runtime env against the checked-in Hermes contract before you retry:

- `HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY` are injected by compose
- some launchers/helpers also need `http_proxy` / `https_proxy` / `no_proxy`
- client-specific trust may require one or more of `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`, `SSL_CERT_FILE`, `CURL_CA_BUNDLE`, or `GIT_SSL_CAINFO`
- all env-based trust paths should point at `/opt/agent-auditor/certs/mitmproxy-ca-cert.pem`

### no Gmail request appears in `requests.jsonl`

Check the runtime env inside the container.

### topology A

```bash
docker compose \
  -f deploy/compose.yaml \
  -f deploy/compose.hermes-forward-proxy.override.yaml \
  --env-file deploy/hermes-forward-proxy.env \
  exec hermes-runtime-real env | grep -E 'HTTP_PROXY|HTTPS_PROXY|NO_PROXY|http_proxy|https_proxy|no_proxy|NODE_EXTRA_CA_CERTS|REQUESTS_CA_BUNDLE|SSL_CERT_FILE|CURL_CA_BUNDLE|GIT_SSL_CAINFO|AGENT_AUDITOR_PROXY_CA_CERT'
```

### topology B

```bash
docker compose \
  -f deploy/compose.yaml \
  -f deploy/compose.hermes-sidecar.override.yaml \
  --env-file deploy/hermes-sidecar.env \
  --profile sidecar \
  exec hermes-runtime-real-sidecar env | grep -E 'HTTP_PROXY|HTTPS_PROXY|NO_PROXY|http_proxy|https_proxy|no_proxy|NODE_EXTRA_CA_CERTS|REQUESTS_CA_BUNDLE|SSL_CERT_FILE|CURL_CA_BUNDLE|GIT_SSL_CAINFO|AGENT_AUDITOR_PROXY_CA_CERT'
```

If those proxy vars are missing or wrong, the runtime is not actually routed through mitmproxy.

### a Gmail request exists, but the path is not `/gmail/v1/users/me/messages/send`

That means the manual Hermes exercise hit a different Google route.
For this handoff, retry with a narrower instruction that explicitly asks Hermes to send one email.

### audit records exist, but they still show `fixture_preview`

That means you are looking at bootstrap preview data instead of the real request path.
Cross-check:

- the newest timestamps
- the `session_id` / `agent_id`
- the Gmail action verb
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
  -f deploy/compose.hermes-forward-proxy.override.yaml \
  --env-file deploy/hermes-forward-proxy.env \
  down
```

### topology B

```bash
docker compose \
  -f deploy/compose.yaml \
  -f deploy/compose.hermes-sidecar.override.yaml \
  --env-file deploy/hermes-sidecar.env \
  --profile sidecar \
  down
```

If Hermes sent a test message as part of the check, handle mailbox cleanup separately and deliberately.
Do not hide that cleanup inside the evidence narrative.

## related docs

- deploy entrypoint: [`../../deploy/README.md`](../../deploy/README.md)
- separate trust-boundary handoff: [`hermes-real-runtime-handoff-separate-trust-boundary.md`](hermes-real-runtime-handoff-separate-trust-boundary.md)
- proxy trust bootstrap: [`real-runtime-proxy-trust-bootstrap-dev.md`](real-runtime-proxy-trust-bootstrap-dev.md)
- audit inspection path: [`real-runtime-audit-inspection-local.md`](real-runtime-audit-inspection-local.md)
- real-runtime readiness boundary: [`../architecture/real-runtime-audit-readiness-boundary.md`](../architecture/real-runtime-audit-readiness-boundary.md)
- real-traffic evidence boundary: [`../architecture/real-traffic-observation-boundary.md`](../architecture/real-traffic-observation-boundary.md)
- GWS runbook: [`hostd-api-network-gws-poc-local.md`](hostd-api-network-gws-poc-local.md)
- live proxy coverage matrix: [`../architecture/live-proxy-coverage-matrix.md`](../architecture/live-proxy-coverage-matrix.md)
