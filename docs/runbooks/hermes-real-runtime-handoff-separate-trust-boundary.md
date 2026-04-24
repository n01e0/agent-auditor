# Hermes real-runtime handoff on a separate trust boundary

This runbook fixes the **human handoff path** for `n01e0` to run one real Hermes verification while keeping the monitored runtime boundary separate from the audit boundary.

Use it when the question is:

> how do I run the Hermes real-runtime exercise when the proxy/runtime stay on the monitored node, `hostd` lives on a remote audit node, and I want the resulting evidence to land outside the monitored target boundary?

This is a **handoff runbook** for the minimum honest remote-audit shape documented in:

- [`../architecture/remote-audit-integrity-boundary.md`](../architecture/remote-audit-integrity-boundary.md)
- [`../architecture/remote-audit-deployment-topology.md`](../architecture/remote-audit-deployment-topology.md)
- [`../architecture/observed-runtime-remote-ingress-contract.md`](../architecture/observed-runtime-remote-ingress-contract.md)

It is intentionally narrower than a production deployment guide.

## what this path proves

Following this runbook lets an operator:

- keep the Hermes runtime + proxy on the **monitored target boundary**
- move `hostd` and the durable audit files onto a **remote audit boundary**
- route redaction-safe observed-runtime envelopes across the checked-in remote-ingress seam
- inspect the remote-side observed-runtime inbox, durable JSONL records, and integrity checkpoint logs
- judge the result honestly as `wiring success`, `observed_request`, or a stronger durable remote-audit artifact

For the current Hermes first exercise, the strongest provider-level claim is still:

- **`observed_request`** for `gmail.users.messages.send`

This separate-boundary runbook does **not** upgrade Hermes/Gmail to `validated_observation`.
It only moves the final evidence copy out of the monitored target boundary.

## what this path does not prove

It does **not** by itself prove:

- production mTLS/authn for remote ingress
- production-ready daemon hardening on every distro
- broad Hermes provider coverage
- inline live hold/deny enforcement
- `validated_observation` for the Hermes/Gmail path

## boundary model

Read the deployment literally as two different trust boundaries:

```text
host A / monitored target boundary
  Hermes runtime
    -> Hermes proxy
    -> optional local spool/debug state
    => network handoff

host B / remote audit boundary
  remote hostd
    -> observed-runtime acceptance
    -> durable audit / approval JSONL
    -> integrity checkpoint logs
    -> local inspection / reviewer export
```

Core rule:

- anything on host A is useful for interception, retry, and debugging
- the investigator-facing evidence should be read from host B
- do not treat a same-host preview/spool copy on host A as the final audit trail

## preferred first exercise

Keep the first remote-boundary Hermes exercise as narrow as the local Hermes handoff:

- one real Hermes container
- topology **A / forward proxy** first
- one Gmail send to a test inbox you control
- semantic action: `gmail.users.messages.send`
- provider authority: `gmail.googleapis.com`

Why keep this route first:

- the existing Hermes handoff already fixes the Gmail-send operator flow
- the current strongest honest Hermes claim stays `observed_request`
- the remote-boundary change here is about **where the evidence lands**, not about changing the provider exercise itself

## before you start

Finish or read these first:

1. local Hermes handoff baseline:
   - [`hermes-real-runtime-handoff-local.md`](hermes-real-runtime-handoff-local.md)
2. proxy trust bootstrap:
   - [`real-runtime-proxy-trust-bootstrap-dev.md`](real-runtime-proxy-trust-bootstrap-dev.md)
3. audit inspection path:
   - [`real-runtime-audit-inspection-local.md`](real-runtime-audit-inspection-local.md)
4. remote boundary notes:
   - [`../architecture/remote-audit-integrity-boundary.md`](../architecture/remote-audit-integrity-boundary.md)
   - [`../architecture/remote-audit-deployment-topology.md`](../architecture/remote-audit-deployment-topology.md)
   - [`../architecture/observed-runtime-remote-ingress-contract.md`](../architecture/observed-runtime-remote-ingress-contract.md)

You also need:

- **host A** for the monitored Hermes runtime/proxy
- **host B** for remote `hostd` and remote durable audit state
- a test inbox you control
- a real Hermes image with the credentials/config needed to reach Gmail
- an exact repository revision checked out on both hosts

## checked-in contract pieces used by this runbook

### monitored side

- Compose base: [`../../deploy/compose.yaml`](../../deploy/compose.yaml)
- real Hermes topology A override: [`../../deploy/compose.hermes-forward-proxy.override.yaml`](../../deploy/compose.hermes-forward-proxy.override.yaml)
- real Hermes topology B override: [`../../deploy/compose.hermes-sidecar.override.yaml`](../../deploy/compose.hermes-sidecar.override.yaml)
- Hermes env samples:
  - [`../../deploy/hermes-forward-proxy.env.sample`](../../deploy/hermes-forward-proxy.env.sample)
  - [`../../deploy/hermes-sidecar.env.sample`](../../deploy/hermes-sidecar.env.sample)

The monitored-side compose contract now exposes:

- `AUDITOR_REMOTE_INGRESS_ADDR`

So the proxy can point at `hostd` on another machine without an ad-hoc compose override.

### remote audit side

- systemd unit: [`../../deploy/systemd/agent-auditor-hostd.service`](../../deploy/systemd/agent-auditor-hostd.service)
- sample env: [`../../deploy/systemd/agent-auditor-hostd.env.sample`](../../deploy/systemd/agent-auditor-hostd.env.sample)

The systemd contract now exposes:

- `AGENT_AUDITOR_HOSTD_REMOTE_INGRESS_LISTEN`

So the remote audit host can publish the checked-in ingress listener explicitly.

## 1. prepare host B as the remote audit node

Use the exact same repository revision you intend to use on host A.

If you are building from source on host B:

```bash
cargo build --release -p agent-auditor-hostd -p agent-auditor-cli
sudo install -Dm755 target/release/agent-auditor-hostd /usr/local/bin/agent-auditor-hostd
sudo install -Dm755 target/release/agent-auditor-cli /usr/local/bin/agent-auditor-cli
```

Install the checked-in service artifacts:

```bash
sudo install -Dm644 deploy/systemd/agent-auditor-hostd.service /etc/systemd/system/agent-auditor-hostd.service
sudo install -Dm644 deploy/systemd/agent-auditor-hostd.env.sample /etc/agent-auditor/agent-auditor-hostd.env
```

Edit `/etc/agent-auditor/agent-auditor-hostd.env` and set at least:

```dotenv
AGENT_AUDITOR_HOSTD_BIN=/usr/local/bin/agent-auditor-hostd
AGENT_AUDITOR_HOSTD_STATE_DIR=/var/lib/agent-auditor-hostd
AGENT_AUDITOR_HOSTD_POLL_INTERVAL_MS=250
AGENT_AUDITOR_HOSTD_REMOTE_INGRESS_LISTEN=0.0.0.0:19090
```

Start and verify the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now agent-auditor-hostd
systemctl status --no-pager agent-auditor-hostd
ss -ltn | grep ':19090'
```

You want host B listening on the configured ingress port before host A starts sending observed-runtime envelopes.

## 2. prepare host A with the Hermes real-runtime env contract

### topology A / recommended first path

```bash
cp deploy/hermes-forward-proxy.env.sample deploy/hermes-forward-proxy.env
cp deploy/hermes-forward-proxy.runtime.env.sample deploy/hermes-forward-proxy.runtime.env
```

Edit `deploy/hermes-forward-proxy.env` and set at least:

- `HERMES_RUNTIME_IMAGE`
- `HERMES_RUNTIME_ENV_FILE` if you renamed it
- `AUDITOR_REMOTE_INGRESS_ADDR=<host-b-or-ip>:19090`

Keep the checked-in lineage contract stable while you verify one runtime:

- `HERMES_SESSION_ID`
- `HERMES_AGENT_ID`
- `HERMES_WORKSPACE_ID`

If Hermes or bundled tooling needs explicit runtime trust env, keep using the same checked-in mounted cert path:

- `/opt/agent-auditor/certs/mitmproxy-ca-cert.pem`

### topology B / sidecar

```bash
cp deploy/hermes-sidecar.env.sample deploy/hermes-sidecar.env
cp deploy/hermes-sidecar.runtime.env.sample deploy/hermes-sidecar.runtime.env
```

Edit `deploy/hermes-sidecar.env` and set at least:

- `HERMES_SIDECAR_RUNTIME_IMAGE`
- `HERMES_SIDECAR_RUNTIME_ENV_FILE` if you renamed it
- `AUDITOR_REMOTE_INGRESS_ADDR=<host-b-or-ip>:19090`

Keep the sidecar lineage contract stable too:

- `SIDECAR_HERMES_SESSION_ID`
- `SIDECAR_HERMES_AGENT_ID`
- `SIDECAR_HERMES_WORKSPACE_ID`

## 3. finish trust bootstrap on host A

Before starting the real runtime, finish the Hermes CA export path from [`real-runtime-proxy-trust-bootstrap-dev.md`](real-runtime-proxy-trust-bootstrap-dev.md).

Minimum check:

```bash
ls -l deploy/local/mitmproxy-ca/hermes/mitmproxy-ca-cert.pem
openssl x509 -in deploy/local/mitmproxy-ca/hermes/mitmproxy-ca-cert.pem -noout -subject -issuer -dates
```

And confirm the real Hermes image trusts the mounted cert path either through its OS trust store or runtime envs such as:

- `NODE_EXTRA_CA_CERTS`
- `REQUESTS_CA_BUNDLE`
- `SSL_CERT_FILE`
- `CURL_CA_BUNDLE`
- `GIT_SSL_CAINFO`

## 4. render the exact monitored-side config

### topology A

```bash
docker compose \
  -f deploy/compose.yaml \
  -f deploy/compose.hermes-forward-proxy.override.yaml \
  --env-file deploy/hermes-forward-proxy.env \
  config
```

### topology B

```bash
docker compose \
  -f deploy/compose.yaml \
  -f deploy/compose.hermes-sidecar.override.yaml \
  --env-file deploy/hermes-sidecar.env \
  --profile sidecar \
  config
```

Verify in the rendered output that the paired Hermes proxy now points at host B:

- `AUDITOR_REMOTE_INGRESS_ADDR=<host-b-or-ip>:19090`

If config render already fails, stop there.

## 5. start only the monitored-side services on host A

For the separate-boundary exercise, do **not** use the local compose `hostd` service as your final evidence path.
Start only the Hermes proxy + real runtime on host A.

### topology A

```bash
docker compose \
  -f deploy/compose.yaml \
  -f deploy/compose.hermes-forward-proxy.override.yaml \
  --env-file deploy/hermes-forward-proxy.env \
  up -d --no-deps hermes-forward-proxy hermes-runtime-real
```

### topology B

```bash
docker compose \
  -f deploy/compose.yaml \
  -f deploy/compose.hermes-sidecar.override.yaml \
  --env-file deploy/hermes-sidecar.env \
  --profile sidecar \
  up -d --no-deps hermes-runtime-real-sidecar hermes-proxy-real-sidecar
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

You want the relevant Hermes runtime + proxy containers healthy on host A, and the remote `hostd` service healthy on host B.

## 6. trigger one intentional Hermes Gmail send

Inside the real Hermes runtime, trigger one explicit Gmail send to a test inbox you control.

Use an instruction equivalent to:

> Send a short test email to `<test-address>` with subject `agent-auditor Hermes remote-boundary test`.

The important part is the resulting provider route, not the exact prompt wording.
You want a real request that maps to:

- authority: `gmail.googleapis.com`
- semantic action: `gmail.users.messages.send`

## 7. first confirm the proxy seam on host A

Look at the monitored-side proxy logs first so you know the runtime actually tried to emit traffic.

### topology A

```bash
docker compose \
  -f deploy/compose.yaml \
  -f deploy/compose.hermes-forward-proxy.override.yaml \
  --env-file deploy/hermes-forward-proxy.env \
  logs --tail=200 hermes-forward-proxy
```

### topology B

```bash
docker compose \
  -f deploy/compose.yaml \
  -f deploy/compose.hermes-sidecar.override.yaml \
  --env-file deploy/hermes-sidecar.env \
  --profile sidecar \
  logs --tail=200 hermes-proxy-real-sidecar
```

This is only the monitored-side wiring view.
Do not treat it as final evidence yet.

## 8. inspect the remote observed-runtime acceptance on host B

Start with the remote-side observed-runtime path:

```bash
find /var/lib/agent-auditor-hostd/agent-auditor-hostd-live-proxy-observed-runtime -maxdepth 3 -type f | sort
```

Inspect the session metadata:

```bash
for file in /var/lib/agent-auditor-hostd/agent-auditor-hostd-live-proxy-observed-runtime/sessions/*/session.json; do
  echo "== $file =="
  jq . "$file"
done
```

Then inspect the Gmail request envelopes:

```bash
for file in /var/lib/agent-auditor-hostd/agent-auditor-hostd-live-proxy-observed-runtime/sessions/*/requests.jsonl; do
  echo "== $file =="
  jq -c 'select(.authority == "gmail.googleapis.com") | {
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
  }' "$file"
done
```

Minimum remote-ingress evidence:

- the file lives on **host B**, not on the monitored runtime host
- `authority="gmail.googleapis.com"`
- `method="post"`
- `path="/gmail/v1/users/me/messages/send"`
- the expected Hermes `session_id` / `agent_id` / `workspace_id`
- `content_retained=false`

If you only have this step, you have **wiring success plus remote ingress acceptance**, but you do not yet have the provider-level durable Hermes result.

## 9. inspect the remote durable audit / approval files on host B

For the current Hermes first path, inspect the GWS store:

```bash
find /var/lib/agent-auditor-hostd -maxdepth 2 \( -name 'audit-records.jsonl' -o -name 'approval-requests.jsonl' -o -name '*.integrity.jsonl' \) | sort
```

### audit records

```bash
jq -c '{
  event_id,
  event_type,
  result_status: .result.status,
  action_verb: .action.verb,
  target: .action.target,
  source_kind: .action.attributes.source_kind,
  observation_provenance: .action.attributes.observation_provenance,
  validation_status: .action.attributes.validation_status,
  session_correlation_status: .action.attributes.session_correlation_status,
  durable_integrity: .integrity,
  durable_storage_lineage: .integrity.storage
}' /var/lib/agent-auditor-hostd/agent-auditor-hostd-gws-poc-store/audit-records.jsonl
```

### approval requests

```bash
jq -c '{
  approval_id,
  event_id,
  status,
  enforcement_status: .enforcement.status,
  action_verb: .request.action_verb,
  target: .request.target,
  observation_provenance: .request.attributes.observation_provenance,
  validation_status: .request.attributes.validation_status,
  session_correlation_status: .request.attributes.session_correlation_status,
  durable_integrity: .integrity,
  durable_storage_lineage: .integrity.storage
}' /var/lib/agent-auditor-hostd/agent-auditor-hostd-gws-poc-store/approval-requests.jsonl
```

Minimum expected Hermes/GWS durable evidence on the remote boundary:

- audit record:
  - `event_type="gws_action"`
  - `action_verb="gmail.users.messages.send"`
  - `observation_provenance="observed_request"`
  - `validation_status="observed_request"`
  - `session_correlation_status="runtime_path_confirmed"`
- approval request:
  - `action_verb="gmail.users.messages.send"`
  - `observation_provenance="observed_request"`
  - `validation_status="observed_request"`
  - `session_correlation_status="runtime_path_confirmed"`
- both durable rows should also carry:
  - `durable_integrity`
  - remote storage lineage (surfaced in raw JSON as `integrity.storage` and in CLI inspection as `durable_storage_lineage`)

That is the current honest Hermes result: **real request observed, reflected durably on the remote audit boundary, but not upgraded to `validated_observation`.**

## 10. inspect the integrity checkpoint logs on host B

The remote durable path also emits checkpoint logs:

```bash
jq -c '{
  stream,
  checkpoint_kind,
  record_count,
  first_record_hash,
  last_record_hash,
  prev_checkpoint_hash,
  checkpoint_hash,
  signing_key_id
}' /var/lib/agent-auditor-hostd/agent-auditor-hostd-gws-poc-store/audit-records.integrity.jsonl
```

```bash
jq -c '{
  stream,
  checkpoint_kind,
  record_count,
  first_record_hash,
  last_record_hash,
  prev_checkpoint_hash,
  checkpoint_hash,
  signing_key_id
}' /var/lib/agent-auditor-hostd/agent-auditor-hostd-gws-poc-store/approval-requests.integrity.jsonl
```

Read these logs conservatively:

- they show the durable remote-side integrity chain/checkpoint material
- they do **not** by themselves change the Hermes provider evidence tier from `observed_request`
- they are the extra remote-boundary evidence that the final copy no longer lives only with the monitored target

## 11. inspect the reviewer-facing local inspection view on host B

Use the CLI on the remote audit host:

```bash
agent-auditor-cli audit tail --state-dir /var/lib/agent-auditor-hostd --kind all --count 20
```

Then show the exact row you care about:

```bash
agent-auditor-cli audit show --state-dir /var/lib/agent-auditor-hostd <event_id_or_approval_id>
```

For the Hermes/Gmail path, the strongest expected `observation_local_inspection` fields are:

- `observation_provenance="observed_request"`
- `validation_status="observed_request"`
- `evidence_tier="observed_request"`
- `session_correlation_status="runtime_path_confirmed"`

And the same `audit show` output should also expose:

- `durable_integrity`
- `durable_storage_lineage`

That is the shortest reviewer-facing summary of both:

1. the Hermes request crossed the proxy seam and remote-ingress boundary
2. the durable copy now lives on the remote audit side

## minimum evidence bundle to save

For this separate-boundary Hermes handoff, save at least:

1. the exact monitored-side `docker compose ... config` command and rendered output
2. the remote `systemctl status agent-auditor-hostd` output from host B
3. one remote observed-runtime `requests.jsonl` line for the Gmail request
4. one remote `audit-records.jsonl` line showing `gmail.users.messages.send`
5. one remote `approval-requests.jsonl` line for the same action
6. one remote `audit-records.integrity.jsonl` checkpoint line
7. one `agent-auditor-cli audit show --state-dir /var/lib/agent-auditor-hostd ...` output
8. the exact Hermes image tag, topology, remote host name/address, and test inbox used

That bundle is enough for another reviewer to judge:

- whether the request really crossed out of the monitored target boundary
- whether the durable copy exists remotely
- whether the Hermes evidence still stops honestly at `observed_request`

## how to read the outcome honestly

### outcome A: monitored-side wiring only

You saw host A proxy logs, but host B has no observed-runtime or durable artifacts.

That means Hermes tried to send traffic, but the remote audit boundary did not accept it.

### outcome B: remote ingress accepted, but no durable GWS row

You saw host B `requests.jsonl`, but not the matching durable GWS audit/approval row.

That means the boundary crossing happened, but the provider-level durable reflection did not complete.

### outcome C: remote durable Hermes observed request

You saw all of:

- remote observed-runtime Gmail envelope on host B
- remote GWS audit/approval rows
- `observation_provenance="observed_request"`
- `validation_status="observed_request"`
- `session_correlation_status="runtime_path_confirmed"`
- remote-side `durable_integrity` / `durable_storage_lineage`

That is the current strongest honest outcome for this runbook.
It proves more than same-host preview storage, but it still does **not** mean Hermes/Gmail is a validated observation path.

## quick troubleshooting branches

### host B is not listening or proxy logs show connect failures

Check on host B:

```bash
systemctl status --no-pager agent-auditor-hostd
journalctl -u agent-auditor-hostd -n 200 --no-pager
ss -ltn | grep ':19090'
```

If the listener is absent, fix the systemd env first.

### rendered compose still points at `hostd:19090`

You did not override `AUDITOR_REMOTE_INGRESS_ADDR` in the Hermes env file used with `--env-file`.

### proxy saw traffic, but host B has no `requests.jsonl`

Treat that as a remote-ingress failure first:

- verify network reachability from host A to host B
- verify the ingress port and address match exactly
- verify host B logs did not reject the session-lineage or append request

### host B has Gmail envelopes, but durable rows still show `fixture_preview`

You are reading bootstrap preview data instead of the real Hermes request.
Cross-check:

- timestamps
- `session_id` / `agent_id` / `workspace_id`
- Gmail action verb
- whether the real runtime sent traffic after host B started listening

### durable row exists, but `session_correlation_status` is not `runtime_path_confirmed`

Treat that as a correlation failure.
Do not upgrade the result beyond ingress capture until lineage is correct.

### Hermes logs show TLS or CA failures

Go back to [`real-runtime-proxy-trust-bootstrap-dev.md`](real-runtime-proxy-trust-bootstrap-dev.md).
For this runbook, do not keep retrying until the Hermes trust path is fixed.

## cleanup

### host A / topology A

```bash
docker compose \
  -f deploy/compose.yaml \
  -f deploy/compose.hermes-forward-proxy.override.yaml \
  --env-file deploy/hermes-forward-proxy.env \
  down
```

### host A / topology B

```bash
docker compose \
  -f deploy/compose.yaml \
  -f deploy/compose.hermes-sidecar.override.yaml \
  --env-file deploy/hermes-sidecar.env \
  --profile sidecar \
  down
```

### host B

If you are done with the exercise entirely:

```bash
sudo systemctl stop agent-auditor-hostd
```

If you want to preserve the evidence bundle, copy it out before deleting or rotating the remote state dir.

## related docs

- deploy entrypoint: [`../../deploy/README.md`](../../deploy/README.md)
- local Hermes handoff: [`hermes-real-runtime-handoff-local.md`](hermes-real-runtime-handoff-local.md)
- proxy trust bootstrap: [`real-runtime-proxy-trust-bootstrap-dev.md`](real-runtime-proxy-trust-bootstrap-dev.md)
- audit inspection path: [`real-runtime-audit-inspection-local.md`](real-runtime-audit-inspection-local.md)
- remote audit integrity boundary: [`../architecture/remote-audit-integrity-boundary.md`](../architecture/remote-audit-integrity-boundary.md)
- remote audit deployment topology: [`../architecture/remote-audit-deployment-topology.md`](../architecture/remote-audit-deployment-topology.md)
- remote ingress contract: [`../architecture/observed-runtime-remote-ingress-contract.md`](../architecture/observed-runtime-remote-ingress-contract.md)
- real-runtime readiness boundary: [`../architecture/real-runtime-audit-readiness-boundary.md`](../architecture/real-runtime-audit-readiness-boundary.md)
- real-traffic evidence boundary: [`../architecture/real-traffic-observation-boundary.md`](../architecture/real-traffic-observation-boundary.md)
