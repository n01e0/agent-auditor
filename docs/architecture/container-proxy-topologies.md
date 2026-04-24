# container proxy topologies

This note fixes the container-first deployment split for routing OpenClaw / Hermes traffic into the checked-in live proxy seam.

## Goal

Support two container wiring patterns without changing the checked-in **local-volume** observed-runtime contract.

- **A / default**: explicit forward proxy per runtime
- **B / optional**: per-agent sidecar proxy

Both paths only emit redaction-safe `GenericLiveActionEnvelope` metadata into the observed runtime path.
They do not claim inline deny / hold enforcement, CA distribution, or production-hardening completeness.

## Shared contract

Regardless of topology, the checked-in Compose/dev path writes into the same hostd local-volume runtime path:

- runtime root: `agent-auditor-hostd-live-proxy-observed-runtime/`
- session root: `sessions/<sanitized_session_id>__<sanitized_agent_id>__<workspace or workspace_none>/`
- files:
  - `metadata.json`
  - `requests.jsonl`

Each JSONL line is a redaction-safe `GenericLiveActionEnvelope` carrying metadata such as:

- request / correlation id
- session / agent / workspace lineage
- method / authority / path
- header class / body class / auth hint
- provider / target hints when derivable
- interception mode

Raw bodies, cookies, tokens, and message content stay out of this contract.

This same-host shared-volume path is still a preview/bring-up contract, not the follow-on remote-audit handoff. The boundary-crossing replacement contract for `live proxy -> remote hostd` is documented in [`observed-runtime-remote-ingress-contract.md`](observed-runtime-remote-ingress-contract.md).

## Topology A: explicit forward proxy

Use one proxy service per runtime and point the runtime at it with `HTTP_PROXY` / `HTTPS_PROXY`.

```text
openclaw-runtime -> openclaw-forward-proxy -> hostd
hermes-runtime   -> hermes-forward-proxy   -> hostd
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
openclaw-runtime-sidecar -> openclaw-proxy-sidecar -> hostd
hermes-runtime-sidecar   -> hermes-proxy-sidecar   -> hostd
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
