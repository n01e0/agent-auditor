# compose real-runtime end-to-end local runbook

This runbook fixes the **compose-based end-to-end verification order** for the P18 real-runtime handoff.

Use it when the question is:

> what exact Compose path should I follow to verify the checked-in OpenClaw / Hermes runtime wiring end to end, and where should I look first when something fails?

This is an **operator verification runbook** for the checked-in Compose assets.
It does not by itself claim that real traffic has already been observed.

## what this path gives you

Following this runbook lets an operator:

- run the checked-in Compose preflight gates before attempting real traffic
- choose one runtime/topology pair without reverse-engineering service names
- verify the stack layer by layer from config render -> container health -> proxy ingress -> durable audit records -> local inspection
- quickly decide whether the result stopped at wiring success, reached `observed_request`, or reached a checked-in `validated_observation` path
- cut failures into the first likely bucket before going deeper into the provider-specific handoff docs

It does **not** prove:

- that every OpenClaw or Hermes feature is covered by the current proxy path
- that every provider route will normalize into a durable audit record
- production-ready trust distribution, retries, or recovery orchestration
- fail-closed inline hold/deny enforcement

## current checked-in verification targets

Pick one target deliberately.
Do **not** try to validate all four runtime/topology combinations in one shot.

### OpenClaw

- preferred first action: GitHub `repos.update_visibility`
- provider authority: `api.github.com`
- strongest checked-in result today: `validated_observation`
- detailed handoff: [`openclaw-real-runtime-handoff-local.md`](openclaw-real-runtime-handoff-local.md)

### Hermes

- preferred first action: Gmail `gmail.users.messages.send`
- provider authority: `gmail.googleapis.com`
- strongest checked-in result today: `observed_request`
- detailed handoff: [`hermes-real-runtime-handoff-local.md`](hermes-real-runtime-handoff-local.md)

### topology A / forward proxy

- runtime reaches a named proxy service over the Compose network
- preferred when you want the most obvious network shape during first verification

### topology B / sidecar proxy

- runtime reaches loopback `127.0.0.1:8080` through a paired proxy container sharing its network namespace
- useful when you specifically want the sidecar deployment shape

## 1. start from one exact revision

Do not mix docs from one revision with Compose files from another.

From the repository root:

```bash
git rev-parse HEAD
```

If you change revisions, rerun the Compose preflight and trust/bootstrap checks from that same revision.

## 2. run the repository-owned preflight gates first

These are the minimum checked-in gates for the Compose path itself:

```bash
docker compose -f deploy/compose.yaml --env-file deploy/compose.env.sample config
```

```bash
docker compose -f deploy/compose.yaml --env-file deploy/compose.env.sample --profile sidecar config
```

```bash
python3 -m py_compile deploy/proxy/mitmproxy-live-proxy.py
```

If any of those fail, stop there.
The runtime-specific handoff is not trustworthy until the baseline Compose/proxy assets render cleanly.

## 3. choose exactly one runtime/topology pair

Use this matrix to pick the next command set.

| runtime | topology | override file | copied env file | copied runtime env file | start command anchor |
|---|---|---|---|---|---|
| OpenClaw | A / forward proxy | `deploy/compose.openclaw-forward-proxy.override.yaml` | `deploy/openclaw-forward-proxy.env` | `deploy/openclaw-forward-proxy.runtime.env` | `openclaw-forward-proxy`, `openclaw-runtime-real` |
| OpenClaw | B / sidecar proxy | `deploy/compose.openclaw-sidecar.override.yaml` | `deploy/openclaw-sidecar.env` | `deploy/openclaw-sidecar.runtime.env` | `openclaw-runtime-real-sidecar`, `openclaw-proxy-real-sidecar` |
| Hermes | A / forward proxy | `deploy/compose.hermes-forward-proxy.override.yaml` | `deploy/hermes-forward-proxy.env` | `deploy/hermes-forward-proxy.runtime.env` | `hermes-forward-proxy`, `hermes-runtime-real` |
| Hermes | B / sidecar proxy | `deploy/compose.hermes-sidecar.override.yaml` | `deploy/hermes-sidecar.env` | `deploy/hermes-sidecar.runtime.env` | `hermes-runtime-real-sidecar`, `hermes-proxy-real-sidecar` |

Copy only the files you actually need for the chosen pair.

## 4. fill in the real runtime image and credentials

At minimum, edit the copied env files so they point at:

- the real runtime image tag
- the copied runtime `env_file:` path if you renamed it
- the runtime-specific credentials/config the real image needs
- any trust-specific env such as `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`, or `SSL_CERT_FILE` if your image relies on them

Do **not** guess here.
If the real image needs extra setup, finish that setup before you start the stack.

## 5. complete trust bootstrap before real HTTPS traffic

Run the trust bootstrap path that matches your chosen runtime/topology:

- [`real-runtime-proxy-trust-bootstrap-dev.md`](real-runtime-proxy-trust-bootstrap-dev.md)

Then verify the exported CA exists:

### OpenClaw

```bash
ls -l deploy/local/mitmproxy-ca/openclaw/mitmproxy-ca-cert.pem
```

### Hermes

```bash
ls -l deploy/local/mitmproxy-ca/hermes/mitmproxy-ca-cert.pem
```

If the cert is missing, or the runtime image still does not trust it, do not move on to the live verification step.

## 6. render the runtime-specific config you actually plan to run

### OpenClaw, topology A

```bash
docker compose \
  -f deploy/compose.yaml \
  -f deploy/compose.openclaw-forward-proxy.override.yaml \
  --env-file deploy/openclaw-forward-proxy.env \
  config
```

### OpenClaw, topology B

```bash
docker compose \
  -f deploy/compose.yaml \
  -f deploy/compose.openclaw-sidecar.override.yaml \
  --env-file deploy/openclaw-sidecar.env \
  --profile sidecar \
  config
```

### Hermes, topology A

```bash
docker compose \
  -f deploy/compose.yaml \
  -f deploy/compose.hermes-forward-proxy.override.yaml \
  --env-file deploy/hermes-forward-proxy.env \
  config
```

### Hermes, topology B

```bash
docker compose \
  -f deploy/compose.yaml \
  -f deploy/compose.hermes-sidecar.override.yaml \
  --env-file deploy/hermes-sidecar.env \
  --profile sidecar \
  config
```

Do not treat later failures as runtime bugs if this render step already fails.
A broken render is still a config problem.

## 7. start only the chosen end-to-end stack

### OpenClaw, topology A

```bash
docker compose \
  -f deploy/compose.yaml \
  -f deploy/compose.openclaw-forward-proxy.override.yaml \
  --env-file deploy/openclaw-forward-proxy.env \
  up -d hostd openclaw-forward-proxy openclaw-runtime-real
```

### OpenClaw, topology B

```bash
docker compose \
  -f deploy/compose.yaml \
  -f deploy/compose.openclaw-sidecar.override.yaml \
  --env-file deploy/openclaw-sidecar.env \
  --profile sidecar \
  up -d hostd openclaw-runtime-real-sidecar openclaw-proxy-real-sidecar
```

### Hermes, topology A

```bash
docker compose \
  -f deploy/compose.yaml \
  -f deploy/compose.hermes-forward-proxy.override.yaml \
  --env-file deploy/hermes-forward-proxy.env \
  up -d hostd hermes-forward-proxy hermes-runtime-real
```

### Hermes, topology B

```bash
docker compose \
  -f deploy/compose.yaml \
  -f deploy/compose.hermes-sidecar.override.yaml \
  --env-file deploy/hermes-sidecar.env \
  --profile sidecar \
  up -d hostd hermes-runtime-real-sidecar hermes-proxy-real-sidecar
```

Then immediately check service state with the same file/profile combination:

```bash
docker compose <same-flags-as-above> ps
```

What you want to see:

- `hostd` is up
- the chosen proxy service is up
- the chosen runtime service is up

If the runtime exits instantly, do not jump to audit inspection yet.
Fix the container startup failure first.

## 8. confirm runtime proxy wiring before sending the real action

Check the proxy env inside the runtime container.

### OpenClaw, topology A

```bash
docker compose \
  -f deploy/compose.yaml \
  -f deploy/compose.openclaw-forward-proxy.override.yaml \
  --env-file deploy/openclaw-forward-proxy.env \
  exec openclaw-runtime-real env | grep -E 'HTTP_PROXY|HTTPS_PROXY|NO_PROXY'
```

### OpenClaw, topology B

```bash
docker compose \
  -f deploy/compose.yaml \
  -f deploy/compose.openclaw-sidecar.override.yaml \
  --env-file deploy/openclaw-sidecar.env \
  --profile sidecar \
  exec openclaw-runtime-real-sidecar env | grep -E 'HTTP_PROXY|HTTPS_PROXY|NO_PROXY'
```

### Hermes, topology A

```bash
docker compose \
  -f deploy/compose.yaml \
  -f deploy/compose.hermes-forward-proxy.override.yaml \
  --env-file deploy/hermes-forward-proxy.env \
  exec hermes-runtime-real env | grep -E 'HTTP_PROXY|HTTPS_PROXY|NO_PROXY'
```

### Hermes, topology B

```bash
docker compose \
  -f deploy/compose.yaml \
  -f deploy/compose.hermes-sidecar.override.yaml \
  --env-file deploy/hermes-sidecar.env \
  --profile sidecar \
  exec hermes-runtime-real-sidecar env | grep -E 'HTTP_PROXY|HTTPS_PROXY|NO_PROXY'
```

Expected shape:

- topology A -> proxy vars point at the named proxy service on `:8080`
- topology B -> proxy vars point at `http://127.0.0.1:8080`

If those values are missing or wrong, the rest of the run will not prove the checked-in proxy seam.

## 9. trigger one deliberate provider action

Use the runtime-specific handoff runbook for the exact operator action:

- OpenClaw -> [`openclaw-real-runtime-handoff-local.md`](openclaw-real-runtime-handoff-local.md)
- Hermes -> [`hermes-real-runtime-handoff-local.md`](hermes-real-runtime-handoff-local.md)

Keep the first action narrow and intentional:

- OpenClaw: one GitHub repo visibility change on a disposable repo
- Hermes: one Gmail send to a test inbox you control

## 10. inspect the result in this order

Always inspect in the same order.
That keeps failures easy to cut.

### layer 1: container/process health

Check logs from the runtime, proxy, and hostd:

```bash
docker compose <same-flags-as-above> logs --tail=200 <runtime-service> <proxy-service> hostd
```

Look first for:

- TLS / certificate failures
- auth failures
- missing config / missing credentials
- container crash loops

### layer 2: proxy ingress

Use the inspection runbook to confirm the request crossed the proxy seam:

- [`real-runtime-audit-inspection-local.md`](real-runtime-audit-inspection-local.md)

Minimum ingress proof:

- the right `authority`
- the right `path` / `target_hint`
- the right `session_id` / `agent_id` / `workspace_id`
- `content_retained=false`

### layer 3: durable audit / approval records

Check whether the provider-level store now contains the expected semantic action:

- OpenClaw / GitHub -> `agent-auditor-hostd-github-poc-store`
- Hermes / GWS -> `agent-auditor-hostd-gws-poc-store`

### layer 4: local inspection view

Use:

```bash
docker compose exec hostd bash -lc 'cargo run -p agent-auditor-cli -- audit tail --state-dir /state --kind all --count 20'
```

and then:

```bash
docker compose exec hostd bash -lc 'cargo run -p agent-auditor-cli -- audit show --state-dir /state <event_id_or_approval_id>'
```

Judge the outcome from `observation_local_inspection`, not from guesswork.

## 11. how to judge the result honestly

### OpenClaw

Possible outcomes:

- **wiring success only**
  - observed-runtime envelope exists
  - but provider-level durable GitHub evidence is missing
- **observed request**
  - durable/local inspection shows `observation_provenance="observed_request"`
  - but not the validated fields
- **validated observation**
  - local inspection shows `validation_status="validated_observation"`
  - `evidence_tier="validated_observation"`
  - `session_correlation_status="runtime_path_confirmed"`

### Hermes

Possible outcomes:

- **wiring success only**
  - observed-runtime envelope exists
  - but provider-level durable GWS evidence is missing
- **observed request**
  - durable/local inspection shows:
    - `observation_provenance="observed_request"`
    - `validation_status="observed_request"`
    - `evidence_tier="observed_request"`
    - `session_correlation_status="runtime_path_confirmed"`

Important rule:

- do **not** promote the Hermes/GWS path to `validated_observation` just because the repository has other validated paths elsewhere

## 12. failure triage map

Start with the first bucket that matches what you saw.

### bucket A: Compose render fails before startup

Typical symptoms:

- `docker compose ... config` exits non-zero
- interpolation errors
- missing env file / missing required variable

First checks:

- did you copy the right `*.env.sample` files to real `*.env` files?
- did you update the runtime image variable for the chosen path?
- if you renamed the runtime env file, did you also update `*_RUNTIME_ENV_FILE`?
- are you accidentally mixing topology A files with topology B commands?

Stop here until render is clean.

### bucket B: containers do not stay up

Typical symptoms:

- `docker compose ps` shows `Exited`
- runtime or proxy restarts in a loop

First checks:

- `docker compose <same-flags> logs --tail=200 <runtime-service> <proxy-service> hostd`
- image pull / entrypoint failures
- bad runtime credentials/config
- wrong sidecar profile usage

If the runtime cannot stay up, you do not have an end-to-end path yet.

### bucket C: runtime is up, but there is no provider request

Typical symptoms:

- runtime logs show no real action
- `requests.jsonl` has no matching provider request

First checks:

- did you actually trigger the narrow provider action from the handoff doc?
- is the runtime authenticated to GitHub or Gmail?
- do runtime env vars show the expected proxy values?
- is the app using a custom network client that ignores `HTTP_PROXY` / `HTTPS_PROXY`?

Treat this as an application/runtime routing problem, not an audit-store problem.

### bucket D: provider request exists, but TLS/cert errors appear

Typical symptoms:

- `certificate verify failed`
- `self signed certificate`
- `unable to get local issuer certificate`

First checks:

- rerun the trust-bootstrap verification
- confirm the correct runtime CA file exists under `deploy/local/mitmproxy-ca/<runtime>/`
- confirm the real image trusts that CA through the OS trust store or explicit env variables
- if you rotated the proxy CA volume, confirm the runtime trust bundle was refreshed too

Special cut for GitHub-backed startup paths:

- if `api.github.com` succeeds under an app-specific env like `NODE_EXTRA_CA_CERTS`, but `github.com` or `raw.githubusercontent.com` still fail with `unknown ca`, the proxy path is usually fine
- the missing piece is that curl/git-style clients still do not trust the mounted mitmproxy CA
- prefer OS trust-store installation in a derived image; otherwise add client-specific env such as `SSL_CERT_FILE`, `CURL_CA_BUNDLE`, and `GIT_SSL_CAINFO` pointing at `/opt/agent-auditor/certs/mitmproxy-ca-cert.pem`

Do not keep retrying provider actions until trust is fixed.

### bucket E: proxy ingress exists, but no durable audit / approval record appears

Typical symptoms:

- `requests.jsonl` shows the live request
- but the expected provider store has no matching record

First checks:

- did the request hit the checked-in action the runbook expects?
  - OpenClaw: `repos.update_visibility`
  - Hermes: `gmail.users.messages.send`
- are you inspecting the correct store path under `/state`?
- do hostd logs show normalization/classification issues?
- did the request use the expected authority/path/target hint?

Treat this as a provider-path mismatch or downstream normalization gap.

### bucket F: durable records exist, but they still say `fixture_preview`

Typical symptoms:

- audit or approval JSONL exists
- `observation_provenance="fixture_preview"`

First checks:

- are you reading old bootstrap records instead of the newest runtime attempt?
- do the timestamps match the current run?
- do `session_id` / `agent_id` / `workspace_id` match the current Compose env contract?
- did the real runtime actually emit traffic after this state dir was initialized?

Do not count that as real-runtime evidence.

### bucket G: durable record exists, but `session_correlation_status` is wrong or missing

Typical symptoms:

- provider-level record exists
- but runtime correlation is not confirmed

First checks:

- did the paired proxy env keep the intended session / agent / workspace identity?
- are you reading the right observed-runtime session directory?
- did you restart only one service and accidentally mix old/new lineage?

Treat that as a correlation failure.
Do not upgrade the evidence beyond observed ingress until it is fixed.

### bucket H: `audit show` output is empty or missing the expected record

Typical symptoms:

- `audit list` / `audit tail` does not show the record you expect
- `audit show` cannot find the id

First checks:

- are you using `--state-dir /state` inside the hostd container?
- do the JSONL files exist under `/state/agent-auditor-hostd*-store/`?
- are you using an id from the current state dir, not from an old run?

This is usually a state-dir or stale-record lookup problem.

## 13. shortest repeatable verification order

If you only want the minimal end-to-end path, use this order:

1. baseline Compose render + proxy script checks
2. choose one runtime/topology pair
3. copy/edit the matching env files
4. complete trust bootstrap for that runtime
5. render the runtime-specific Compose config
6. start only the chosen stack
7. confirm runtime proxy env vars
8. trigger one deliberate provider action
9. confirm proxy ingress under `requests.jsonl`
10. confirm durable audit/approval records
11. confirm `observation_local_inspection`
12. classify the result as `wiring success`, `observed_request`, or `validated_observation` when the checked-in path really supports it

## 14. cleanup after each attempt

Use the same flags you used for startup.

### topology A

```bash
docker compose <same-flags-as-above> down
```

### topology B

```bash
docker compose <same-flags-as-above> --profile sidecar down
```

If you need a fresh dev CA, rotate only the matching named volume as described in [`real-runtime-proxy-trust-bootstrap-dev.md`](real-runtime-proxy-trust-bootstrap-dev.md).

## related docs

- deploy entrypoint: [`../../deploy/README.md`](../../deploy/README.md)
- real-runtime readiness boundary: [`../architecture/real-runtime-audit-readiness-boundary.md`](../architecture/real-runtime-audit-readiness-boundary.md)
- trust bootstrap: [`real-runtime-proxy-trust-bootstrap-dev.md`](real-runtime-proxy-trust-bootstrap-dev.md)
- audit inspection: [`real-runtime-audit-inspection-local.md`](real-runtime-audit-inspection-local.md)
- OpenClaw handoff: [`openclaw-real-runtime-handoff-local.md`](openclaw-real-runtime-handoff-local.md)
- Hermes handoff: [`hermes-real-runtime-handoff-local.md`](hermes-real-runtime-handoff-local.md)
- real-traffic evidence boundary: [`../architecture/real-traffic-observation-boundary.md`](../architecture/real-traffic-observation-boundary.md)
