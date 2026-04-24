# container proxy topologies

This note fixes the container-first deployment split for routing OpenClaw / Hermes traffic into the checked-in live proxy seam.

## Goal

Support two container wiring patterns while sending the checked-in redaction-safe live envelope over the `live proxy -> remote hostd` ingress boundary instead of requiring proxy-side shared-volume writes.

- **A / default**: explicit forward proxy per runtime
- **B / optional**: per-agent sidecar proxy

Both paths only emit redaction-safe `GenericLiveActionEnvelope` metadata into the remote ingress path owned by `hostd`.
They do not claim inline deny / hold enforcement, CA distribution, or production-hardening completeness.

## Shared contract

Regardless of topology, the checked-in Compose/dev path sends the same logical units into `hostd` remote ingress acceptance:

- one idempotent session-lineage bootstrap carrying `session_id`, `agent_id`, and optional `workspace_id`
- ordered `GenericLiveActionEnvelope` appends with stable `request_id`
- an acceptance response from `hostd` so the proxy can retry safely without owning the remote cursor

After acceptance, `hostd` persists the resulting observed-runtime state under its own runtime root:

- runtime root: `agent-auditor-hostd-live-proxy-observed-runtime/`
- session root: `sessions/<sanitized_session_id>__<sanitized_agent_id>__<workspace or workspace_none>/`
- files:
  - `session.json`
  - `requests.jsonl`

Each JSONL line is a redaction-safe `GenericLiveActionEnvelope` carrying metadata such as:

- request / correlation id
- session / agent / workspace lineage
- method / authority / path
- header class / body class / auth hint
- provider / target hints when derivable
- interception mode

Raw bodies, cookies, tokens, and message content stay out of this contract.

The checked-in Compose path now uses the boundary-crossing `live proxy -> remote hostd` contract documented in [`observed-runtime-remote-ingress-contract.md`](observed-runtime-remote-ingress-contract.md), while still keeping `hostd`-owned `/state` output available for preview/debug inspection after acceptance.

## Topology A: explicit forward proxy

Use one proxy service per runtime and point the runtime at it with `HTTP_PROXY` / `HTTPS_PROXY`.

```text
openclaw-runtime -> openclaw-forward-proxy => remote ingress => hostd
hermes-runtime   -> hermes-forward-proxy   => remote ingress => hostd
```

Choose A when:

- the runtime already supports `HTTP_PROXY` / `HTTPS_PROXY`
- you want the simplest container boundary
- you want one proxy port per runtime for debugging
- you do not need shared network namespaces

This is the default compose path.

## Topology B: per-agent sidecar proxy

Use one proxy sidecar in the same network namespace as the runtime and point the runtime at `127.0.0.1:8080`.

```text
openclaw-runtime-sidecar -> openclaw-proxy-sidecar => remote ingress => hostd
hermes-runtime-sidecar   -> hermes-proxy-sidecar   => remote ingress => hostd
```

Choose B when:

- the runtime should only see a loopback proxy endpoint
- you want the proxy lifecycle tightly coupled to one runtime container
- you prefer a sidecar-style deployment shape for later orchestration

In Compose this is enabled with `--profile sidecar` and `network_mode: service:<runtime>`.

## Non-goals

This split does not yet provide:

- browser relay deployment
- automatic CA trust bootstrapping
- transparent TLS interception outside an explicit proxy path
- production auth / cert distribution guidance
- inline live deny / hold guarantees

Those belong to later deployment and enforcement phases.
