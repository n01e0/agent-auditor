# deploy/

This directory is reserved for deployment assets.

## Current state

Deployment packaging is still minimal. The repository currently ships architecture notes and local runbooks before a full deployment stack.

## What exists today

- documentation for deployment hardening minimums:
  - [`../docs/architecture/deployment-hardening-minimums.md`](../docs/architecture/deployment-hardening-minimums.md)
- container proxy topology boundary for OpenClaw / Hermes:
  - [`../docs/architecture/container-proxy-topologies.md`](../docs/architecture/container-proxy-topologies.md)
- real-runtime audit readiness boundary for the handoff from stand-in runtimes to real OpenClaw / Hermes verification:
  - [`../docs/architecture/real-runtime-audit-readiness-boundary.md`](../docs/architecture/real-runtime-audit-readiness-boundary.md)
- the current source-of-truth runbook for a separate-machine audit preview setup:
  - [`../docs/runbooks/separate-machine-audit-preview-local.md`](../docs/runbooks/separate-machine-audit-preview-local.md)
- the current source-of-truth runbook for dev proxy trust bootstrap before real HTTPS traffic:
  - [`../docs/runbooks/real-runtime-proxy-trust-bootstrap-dev.md`](../docs/runbooks/real-runtime-proxy-trust-bootstrap-dev.md)
- the current source-of-truth runbook for inspecting observed-runtime envelopes, audit records, and local inspection output during the real-runtime handoff:
  - [`../docs/runbooks/real-runtime-audit-inspection-local.md`](../docs/runbooks/real-runtime-audit-inspection-local.md)
- the current source-of-truth handoff for `n01e0` to run one real OpenClaw verification and collect the expected evidence:
  - [`../docs/runbooks/openclaw-real-runtime-handoff-local.md`](../docs/runbooks/openclaw-real-runtime-handoff-local.md)
- local developer runbooks under:
  - [`../docs/runbooks/README.md`](../docs/runbooks/README.md)
- a systemd service artifact + sample environment config for source-tree-independent hostd startup:
  - [`systemd/agent-auditor-hostd.service`](systemd/agent-auditor-hostd.service)
  - [`systemd/agent-auditor-hostd.env.sample`](systemd/agent-auditor-hostd.env.sample)
- a container-first compose example for live proxy experimentation:
  - [`compose.yaml`](compose.yaml)
  - [`compose.env.sample`](compose.env.sample)
  - [`compose.openclaw-forward-proxy.override.yaml`](compose.openclaw-forward-proxy.override.yaml)
  - [`compose.hermes-forward-proxy.override.yaml`](compose.hermes-forward-proxy.override.yaml)
  - [`compose.openclaw-sidecar.override.yaml`](compose.openclaw-sidecar.override.yaml)
  - [`compose.hermes-sidecar.override.yaml`](compose.hermes-sidecar.override.yaml)
  - [`openclaw-forward-proxy.env.sample`](openclaw-forward-proxy.env.sample)
  - [`openclaw-forward-proxy.runtime.env.sample`](openclaw-forward-proxy.runtime.env.sample)
  - [`hermes-forward-proxy.env.sample`](hermes-forward-proxy.env.sample)
  - [`hermes-forward-proxy.runtime.env.sample`](hermes-forward-proxy.runtime.env.sample)
  - [`openclaw-sidecar.env.sample`](openclaw-sidecar.env.sample)
  - [`openclaw-sidecar.runtime.env.sample`](openclaw-sidecar.runtime.env.sample)
  - [`hermes-sidecar.env.sample`](hermes-sidecar.env.sample)
  - [`hermes-sidecar.runtime.env.sample`](hermes-sidecar.runtime.env.sample)
  - [`proxy/mitmproxy-live-proxy.py`](proxy/mitmproxy-live-proxy.py)

## Compose topologies

`compose.yaml` now ships two proxy topologies that write into the same hostd observed-runtime contract.
The boundary and non-goals are fixed in [`../docs/architecture/container-proxy-topologies.md`](../docs/architecture/container-proxy-topologies.md).

- **A / default**: explicit forward proxy per runtime
  - `openclaw-runtime -> openclaw-forward-proxy -> hostd`
  - `hermes-runtime -> hermes-forward-proxy -> hostd`
- **B / optional profile**: per-agent sidecar proxy
  - `openclaw-runtime-sidecar -> openclaw-proxy-sidecar -> hostd`
  - `hermes-runtime-sidecar -> hermes-proxy-sidecar -> hostd`

The default path is A. Enable B with `--profile sidecar`.

## Quick start

```bash
cp deploy/compose.env.sample deploy/compose.env

docker compose -f deploy/compose.yaml --env-file deploy/compose.env config

docker compose -f deploy/compose.yaml --env-file deploy/compose.env up hostd openclaw-forward-proxy hermes-forward-proxy openclaw-runtime hermes-runtime
```

To add the sidecar examples too:

```bash
docker compose -f deploy/compose.yaml --env-file deploy/compose.env --profile sidecar up
```

The runtime services in the compose file are smoke-friendly stand-ins built with `curlimages/curl`.
Replace their `image` / `command` with the real OpenClaw or Hermes container while keeping the same proxy env wiring.

That swap should be read through [`../docs/architecture/real-runtime-audit-readiness-boundary.md`](../docs/architecture/real-runtime-audit-readiness-boundary.md): the checked-in compose file currently proves stand-in topology smoke, while later P18 work is what makes the repository genuinely handoff-ready for human-run OpenClaw / Hermes verification.

## Dev trust bootstrap before real HTTPS traffic

P18-5 adds the dev-minimum CA / trust bootstrap path in [`../docs/runbooks/real-runtime-proxy-trust-bootstrap-dev.md`](../docs/runbooks/real-runtime-proxy-trust-bootstrap-dev.md).

Important contract points:

- proxy CA state is now persisted per runtime identity via named volumes:
  - `openclaw-mitmproxy-ca`
  - `hermes-mitmproxy-ca`
- the forward-proxy and sidecar-proxy services for the same runtime intentionally share that CA volume
- the repository-owned path stops after CA mint/export, trust installation planning, and runtime env prep; the later handoff task is what actually starts real OpenClaw / Hermes traffic
- only `mitmproxy-ca-cert.pem` should be distributed to runtime trust stores; the private-key bundle is not part of the trust-distribution handoff

## Inspecting observed-runtime and audit output

P18-6 adds the inspection runbook for the real-runtime handoff in [`../docs/runbooks/real-runtime-audit-inspection-local.md`](../docs/runbooks/real-runtime-audit-inspection-local.md).

It fixes the minimum path for:

- finding `/state/agent-auditor-hostd-live-proxy-observed-runtime/.../requests.jsonl`
- locating the durable `/state/agent-auditor-hostd*-store/` audit and approval files
- using `agent-auditor-cli audit ... --state-dir /state` to derive the checked-in local inspection view
- distinguishing plain wiring success from `observed_request` and `validated_observation`

## OpenClaw real-runtime handoff

P18-7 adds the OpenClaw-specific operator handoff in [`../docs/runbooks/openclaw-real-runtime-handoff-local.md`](../docs/runbooks/openclaw-real-runtime-handoff-local.md).

That runbook fixes:

- the exact topology A / B launch commands for the real OpenClaw container
- the preferred first real action (`repos.update_visibility` against a disposable GitHub repo)
- the minimum evidence bundle `n01e0` should save
- the decision rule for `wiring success` vs `observed_request` vs `validated_observation`

## OpenClaw real runtime on topology A / forward proxy

P18-2 adds the first checked-in real-runtime replacement contract for OpenClaw on the default forward-proxy topology.

Files:

- compose override: [`compose.openclaw-forward-proxy.override.yaml`](compose.openclaw-forward-proxy.override.yaml)
- compose interpolation env sample: [`openclaw-forward-proxy.env.sample`](openclaw-forward-proxy.env.sample)
- runtime `env_file:` sample: [`openclaw-forward-proxy.runtime.env.sample`](openclaw-forward-proxy.runtime.env.sample)

Use it like this:

```bash
cp deploy/openclaw-forward-proxy.env.sample deploy/openclaw-forward-proxy.env
cp deploy/openclaw-forward-proxy.runtime.env.sample deploy/openclaw-forward-proxy.runtime.env

# Edit at least:
# - OPENCLAW_RUNTIME_IMAGE
# - OPENCLAW_RUNTIME_ENV_FILE (if you renamed the runtime env file)
# - runtime-specific secrets/config inside deploy/openclaw-forward-proxy.runtime.env

docker compose \
  -f deploy/compose.yaml \
  -f deploy/compose.openclaw-forward-proxy.override.yaml \
  --env-file deploy/openclaw-forward-proxy.env \
  config

docker compose \
  -f deploy/compose.yaml \
  -f deploy/compose.openclaw-forward-proxy.override.yaml \
  --env-file deploy/openclaw-forward-proxy.env \
  up hostd openclaw-forward-proxy openclaw-runtime-real
```

Contract notes:

- `openclaw-runtime-real` is a new service name on purpose; it lets the checked-in `openclaw-runtime` stand-in stay available for smoke use while the real container wiring is tested separately.
- `openclaw-runtime-real` uses the real image's default entrypoint/command. The override only injects proxy env plus `env_file:`.
- the paired `openclaw-forward-proxy` service still owns `OPENCLAW_SESSION_ID`, `OPENCLAW_AGENT_ID`, and `OPENCLAW_WORKSPACE_ID`; that is the lineage that reaches hostd observed-runtime storage.
- `OPENCLAW_RUNTIME_HTTP_PROXY` / `OPENCLAW_RUNTIME_HTTPS_PROXY` default to `http://openclaw-forward-proxy:8080` so the real container stays on topology A.
- dev trust bootstrap for HTTPS interception is documented separately in [`../docs/runbooks/real-runtime-proxy-trust-bootstrap-dev.md`](../docs/runbooks/real-runtime-proxy-trust-bootstrap-dev.md). Production CA distribution is still out of scope.

## Hermes real runtime on topology A / forward proxy

P18-3 adds the checked-in real-runtime replacement contract for Hermes on the default forward-proxy topology.

Files:

- compose override: [`compose.hermes-forward-proxy.override.yaml`](compose.hermes-forward-proxy.override.yaml)
- compose interpolation env sample: [`hermes-forward-proxy.env.sample`](hermes-forward-proxy.env.sample)
- runtime `env_file:` sample: [`hermes-forward-proxy.runtime.env.sample`](hermes-forward-proxy.runtime.env.sample)

Use it like this:

```bash
cp deploy/hermes-forward-proxy.env.sample deploy/hermes-forward-proxy.env
cp deploy/hermes-forward-proxy.runtime.env.sample deploy/hermes-forward-proxy.runtime.env

# Edit at least:
# - HERMES_RUNTIME_IMAGE
# - HERMES_RUNTIME_ENV_FILE (if you renamed the runtime env file)
# - runtime-specific secrets/config inside deploy/hermes-forward-proxy.runtime.env

docker compose \
  -f deploy/compose.yaml \
  -f deploy/compose.hermes-forward-proxy.override.yaml \
  --env-file deploy/hermes-forward-proxy.env \
  config

docker compose \
  -f deploy/compose.yaml \
  -f deploy/compose.hermes-forward-proxy.override.yaml \
  --env-file deploy/hermes-forward-proxy.env \
  up hostd hermes-forward-proxy hermes-runtime-real
```

Contract notes:

- `hermes-runtime-real` is a new service name on purpose; it lets the checked-in `hermes-runtime` stand-in stay available for smoke use while the real container wiring is tested separately.
- `hermes-runtime-real` uses the real image's default entrypoint/command. The override only injects proxy env plus `env_file:`.
- the paired `hermes-forward-proxy` service still owns `HERMES_SESSION_ID`, `HERMES_AGENT_ID`, and `HERMES_WORKSPACE_ID`; that is the lineage that reaches hostd observed-runtime storage.
- `HERMES_RUNTIME_HTTP_PROXY` / `HERMES_RUNTIME_HTTPS_PROXY` default to `http://hermes-forward-proxy:8080` so the real container stays on topology A.
- dev trust bootstrap for HTTPS interception is documented separately in [`../docs/runbooks/real-runtime-proxy-trust-bootstrap-dev.md`](../docs/runbooks/real-runtime-proxy-trust-bootstrap-dev.md). Production CA distribution is still out of scope.

## OpenClaw real runtime on topology B / sidecar profile

P18-4 adds the checked-in real-runtime replacement contract for OpenClaw on the optional sidecar profile.

Files:

- compose override: [`compose.openclaw-sidecar.override.yaml`](compose.openclaw-sidecar.override.yaml)
- compose interpolation env sample: [`openclaw-sidecar.env.sample`](openclaw-sidecar.env.sample)
- runtime `env_file:` sample: [`openclaw-sidecar.runtime.env.sample`](openclaw-sidecar.runtime.env.sample)

Use it like this:

```bash
cp deploy/openclaw-sidecar.env.sample deploy/openclaw-sidecar.env
cp deploy/openclaw-sidecar.runtime.env.sample deploy/openclaw-sidecar.runtime.env

# Edit at least:
# - OPENCLAW_SIDECAR_RUNTIME_IMAGE
# - OPENCLAW_SIDECAR_RUNTIME_ENV_FILE (if you renamed the runtime env file)
# - runtime-specific secrets/config inside deploy/openclaw-sidecar.runtime.env

docker compose \
  -f deploy/compose.yaml \
  -f deploy/compose.openclaw-sidecar.override.yaml \
  --env-file deploy/openclaw-sidecar.env \
  --profile sidecar \
  config

docker compose \
  -f deploy/compose.yaml \
  -f deploy/compose.openclaw-sidecar.override.yaml \
  --env-file deploy/openclaw-sidecar.env \
  --profile sidecar \
  up hostd openclaw-runtime-real-sidecar openclaw-proxy-real-sidecar
```

Contract notes:

- `openclaw-runtime-real-sidecar` and `openclaw-proxy-real-sidecar` are new service names on purpose; they let the checked-in sidecar stand-ins stay available for smoke use while the real container wiring is tested separately.
- `openclaw-runtime-real-sidecar` uses the real image's default entrypoint/command. The override only injects proxy env plus `env_file:`.
- `openclaw-proxy-real-sidecar` shares the runtime network namespace with `network_mode: service:openclaw-runtime-real-sidecar`, so the real container reaches the loopback proxy at `127.0.0.1:8080`.
- the paired sidecar proxy still owns `SIDECAR_OPENCLAW_SESSION_ID`, `SIDECAR_OPENCLAW_AGENT_ID`, and `SIDECAR_OPENCLAW_WORKSPACE_ID`; that is the lineage that reaches hostd observed-runtime storage.
- `OPENCLAW_SIDECAR_RUNTIME_HTTP_PROXY` / `OPENCLAW_SIDECAR_RUNTIME_HTTPS_PROXY` default to `http://127.0.0.1:8080` so the real container stays on topology B.
- `openclaw-proxy-real-sidecar` also reuses the persisted `openclaw-mitmproxy-ca` volume, so you can mint/export the CA before you start the real sidecar runtime.
- dev trust bootstrap for HTTPS interception is documented separately in [`../docs/runbooks/real-runtime-proxy-trust-bootstrap-dev.md`](../docs/runbooks/real-runtime-proxy-trust-bootstrap-dev.md). Production CA distribution is still out of scope.

## Hermes real runtime on topology B / sidecar profile

P18-4 also adds the checked-in real-runtime replacement contract for Hermes on the optional sidecar profile.

Files:

- compose override: [`compose.hermes-sidecar.override.yaml`](compose.hermes-sidecar.override.yaml)
- compose interpolation env sample: [`hermes-sidecar.env.sample`](hermes-sidecar.env.sample)
- runtime `env_file:` sample: [`hermes-sidecar.runtime.env.sample`](hermes-sidecar.runtime.env.sample)

Use it like this:

```bash
cp deploy/hermes-sidecar.env.sample deploy/hermes-sidecar.env
cp deploy/hermes-sidecar.runtime.env.sample deploy/hermes-sidecar.runtime.env

# Edit at least:
# - HERMES_SIDECAR_RUNTIME_IMAGE
# - HERMES_SIDECAR_RUNTIME_ENV_FILE (if you renamed the runtime env file)
# - runtime-specific secrets/config inside deploy/hermes-sidecar.runtime.env

docker compose \
  -f deploy/compose.yaml \
  -f deploy/compose.hermes-sidecar.override.yaml \
  --env-file deploy/hermes-sidecar.env \
  --profile sidecar \
  config

docker compose \
  -f deploy/compose.yaml \
  -f deploy/compose.hermes-sidecar.override.yaml \
  --env-file deploy/hermes-sidecar.env \
  --profile sidecar \
  up hostd hermes-runtime-real-sidecar hermes-proxy-real-sidecar
```

Contract notes:

- `hermes-runtime-real-sidecar` and `hermes-proxy-real-sidecar` are new service names on purpose; they let the checked-in sidecar stand-ins stay available for smoke use while the real container wiring is tested separately.
- `hermes-runtime-real-sidecar` uses the real image's default entrypoint/command. The override only injects proxy env plus `env_file:`.
- `hermes-proxy-real-sidecar` shares the runtime network namespace with `network_mode: service:hermes-runtime-real-sidecar`, so the real container reaches the loopback proxy at `127.0.0.1:8080`.
- the paired sidecar proxy still owns `SIDECAR_HERMES_SESSION_ID`, `SIDECAR_HERMES_AGENT_ID`, and `SIDECAR_HERMES_WORKSPACE_ID`; that is the lineage that reaches hostd observed-runtime storage.
- `HERMES_SIDECAR_RUNTIME_HTTP_PROXY` / `HERMES_SIDECAR_RUNTIME_HTTPS_PROXY` default to `http://127.0.0.1:8080` so the real container stays on topology B.
- `hermes-proxy-real-sidecar` also reuses the persisted `hermes-mitmproxy-ca` volume, so you can mint/export the CA before you start the real sidecar runtime.
- dev trust bootstrap for HTTPS interception is documented separately in [`../docs/runbooks/real-runtime-proxy-trust-bootstrap-dev.md`](../docs/runbooks/real-runtime-proxy-trust-bootstrap-dev.md). Production CA distribution is still out of scope.

## Planned contents

- Kubernetes manifests or Helm later
- system prerequisites for eBPF + fanotify paths
- stronger production certificate distribution / trust bootstrapping

For the current minimum separate-machine preview path, start with [`../docs/runbooks/separate-machine-audit-preview-local.md`](../docs/runbooks/separate-machine-audit-preview-local.md).
