# real-runtime proxy trust bootstrap (dev minimum)

This runbook fixes the **minimum dev CA / trust bootstrap path** for attempting HTTPS interception through the checked-in mitmproxy seam before `n01e0` runs real OpenClaw or Hermes traffic.

Use this when the question is:

> what do I need to do so a real runtime can trust the checked-in mitmproxy CA, without guessing hidden steps or claiming production readiness?

This is a **development trust bootstrap** runbook, not a production certificate-distribution design.

## what this path proves

Following this runbook prepares the repository right up to the point where a human can start a real OpenClaw or Hermes container and let HTTPS traffic flow through mitmproxy.

It gives you:

- a stable per-runtime mitmproxy CA volume for OpenClaw and Hermes
- commands to mint the CA material without reverse-engineering container paths
- commands to export only the public CA certificate for runtime trust installation
- a small decision tree for getting the cert trusted inside a real runtime image
- a stop point before real traffic is actually sent

It does **not** prove:

- that OpenClaw or Hermes has already emitted a real observed request
- that the CA distribution path is production-ready
- that every runtime image family can install trust the same way
- that inline deny / hold is production-safe

## shared CA volume contract

`deploy/compose.yaml` now persists mitmproxy CA state per runtime identity:

- `openclaw-mitmproxy-ca`
- `hermes-mitmproxy-ca`

The important dev rule is:

- OpenClaw forward-proxy and sidecar-proxy services reuse `openclaw-mitmproxy-ca`
- Hermes forward-proxy and sidecar-proxy services reuse `hermes-mitmproxy-ca`

That means you can mint the CA once via the forward-proxy service and later reuse the same CA when you switch to the sidecar topology for the same runtime.

## 1. choose the runtime you are preparing

Pick one target first:

- OpenClaw
- Hermes

Pick one eventual topology too:

- **A / forward proxy**
- **B / sidecar proxy**

Even if the final verification will use topology **B**, this runbook mints the CA from the matching forward-proxy service because it can start without booting the real runtime first and it shares the same persisted CA volume.

## 2. render the config you intend to use later

### OpenClaw, topology A

```bash
docker compose \
  -f deploy/compose.yaml \
  -f deploy/compose.openclaw-forward-proxy.override.yaml \
  --env-file deploy/openclaw-forward-proxy.env.sample \
  config
```

### OpenClaw, topology B

```bash
docker compose \
  -f deploy/compose.yaml \
  -f deploy/compose.openclaw-sidecar.override.yaml \
  --env-file deploy/openclaw-sidecar.env.sample \
  --profile sidecar \
  config
```

### Hermes, topology A

```bash
docker compose \
  -f deploy/compose.yaml \
  -f deploy/compose.hermes-forward-proxy.override.yaml \
  --env-file deploy/hermes-forward-proxy.env.sample \
  config
```

### Hermes, topology B

```bash
docker compose \
  -f deploy/compose.yaml \
  -f deploy/compose.hermes-sidecar.override.yaml \
  --env-file deploy/hermes-sidecar.env.sample \
  --profile sidecar \
  config
```

Do this first so the later trust bootstrap is tied to the same revision and service contract.

## 3. mint the proxy CA without starting the real runtime

### OpenClaw CA mint

```bash
docker compose \
  -f deploy/compose.yaml \
  --env-file deploy/compose.env.sample \
  up -d hostd openclaw-forward-proxy
```

### Hermes CA mint

```bash
docker compose \
  -f deploy/compose.yaml \
  --env-file deploy/compose.env.sample \
  up -d hostd hermes-forward-proxy
```

Mitmproxy writes CA state under `/home/mitmproxy/.mitmproxy/` inside the proxy container. Because that path is backed by the per-runtime named volume, the CA will still be there when you later use the matching real-runtime proxy service.

Quick inspection:

```bash
docker compose -f deploy/compose.yaml --env-file deploy/compose.env.sample exec openclaw-forward-proxy \
  ls -1 /home/mitmproxy/.mitmproxy

docker compose -f deploy/compose.yaml --env-file deploy/compose.env.sample exec hermes-forward-proxy \
  ls -1 /home/mitmproxy/.mitmproxy
```

You should see files such as:

- `mitmproxy-ca-cert.pem`
- `mitmproxy-ca.p12`
- `mitmproxy-ca.pem`

## 4. export only the public CA certificate

Do **not** distribute the private-key bundle (`mitmproxy-ca.pem`) into other machines or images.
The dev minimum is to export only `mitmproxy-ca-cert.pem`.

### OpenClaw export

```bash
mkdir -p deploy/local/mitmproxy-ca/openclaw

docker compose -f deploy/compose.yaml --env-file deploy/compose.env.sample cp \
  openclaw-forward-proxy:/home/mitmproxy/.mitmproxy/mitmproxy-ca-cert.pem \
  deploy/local/mitmproxy-ca/openclaw/mitmproxy-ca-cert.pem
```

### Hermes export

```bash
mkdir -p deploy/local/mitmproxy-ca/hermes

docker compose -f deploy/compose.yaml --env-file deploy/compose.env.sample cp \
  hermes-forward-proxy:/home/mitmproxy/.mitmproxy/mitmproxy-ca-cert.pem \
  deploy/local/mitmproxy-ca/hermes/mitmproxy-ca-cert.pem
```

Optional host-side sanity check:

```bash
openssl x509 -in deploy/local/mitmproxy-ca/openclaw/mitmproxy-ca-cert.pem -noout -subject -issuer -dates
openssl x509 -in deploy/local/mitmproxy-ca/hermes/mitmproxy-ca-cert.pem -noout -subject -issuer -dates
```

## 5. install trust into the real runtime image or container

This is the part that stays runtime-specific.
The repository now gives you the CA certificate and the exact proxy wiring, but you still need to make the real image trust that CA.

### recommended dev path: derive a local image and update the OS trust store

If the image has a shell and package tooling, the cleanest dev path is usually a small derived image.

#### Debian / Ubuntu style images

```Dockerfile
FROM <your-real-runtime-image>
COPY deploy/local/mitmproxy-ca/<runtime>/mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/agent-auditor-mitmproxy.crt
RUN update-ca-certificates
```

#### Alpine style images

```Dockerfile
FROM <your-real-runtime-image>
RUN apk add --no-cache ca-certificates
COPY deploy/local/mitmproxy-ca/<runtime>/mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/agent-auditor-mitmproxy.crt
RUN update-ca-certificates
```

Then point the relevant `*_RUNTIME_IMAGE` variable at that derived image in your copied env file.

### fallback dev path: runtime-specific trust env knobs

If the image already trusts a custom bundle path or app-specific CA variable, put that in the copied runtime `env_file:`.

Common examples:

- `NODE_EXTRA_CA_CERTS=/path/in/container/to/mitmproxy-ca-cert.pem`
- `REQUESTS_CA_BUNDLE=/path/in/container/to/mitmproxy-ca-cert.pem`
- `SSL_CERT_FILE=/path/in/container/to/combined-ca-bundle.pem`

The repository ships these as comments in the runtime env samples so the operator can fill in the one that matches the real image.

### if the image is distroless / scratch / otherwise sealed

Treat that as a manual packaging task.
Do not guess inside the live verification run.
Prepare a dev-only derived image or image-specific trust plan first, then come back to the handoff step.

## 6. copy the runtime env samples and record the trust choice

Examples:

```bash
cp deploy/openclaw-forward-proxy.runtime.env.sample deploy/openclaw-forward-proxy.runtime.env
cp deploy/openclaw-sidecar.runtime.env.sample deploy/openclaw-sidecar.runtime.env
cp deploy/hermes-forward-proxy.runtime.env.sample deploy/hermes-forward-proxy.runtime.env
cp deploy/hermes-sidecar.runtime.env.sample deploy/hermes-sidecar.runtime.env
```

Then edit only the file that matches the real-runtime path you plan to run next.

Record:

- the real image tag you will use
- whether trust is baked into the image or injected via runtime env
- the in-container certificate path, if you use env-based trust

## 7. stop at the preflight boundary

At this point you should have all of the following without having sent real runtime traffic yet:

- the chosen Compose config renders cleanly
- the matching mitmproxy CA has been minted and persisted
- `mitmproxy-ca-cert.pem` has been exported to the repo-local dev path
- the real runtime image trust plan is decided
- the copied runtime env file contains any trust-specific variables the image needs

That is the end of the P18-5 preparation boundary.
The next step is the OpenClaw/Hermes handoff flow that actually starts the real runtime and inspects the resulting evidence.

## cleanup / rotate the dev CA

If you need to throw away the current dev CA and mint a fresh one, remove only the matching named volume:

```bash
docker volume rm agent-auditor-proxy-stack_openclaw-mitmproxy-ca
docker volume rm agent-auditor-proxy-stack_hermes-mitmproxy-ca
```

Then rerun the CA mint step.

Be careful: a fresh CA means any previously prepared runtime trust bundle is now stale.

## related docs

- deploy entrypoint: [`../../deploy/README.md`](../../deploy/README.md)
- real-runtime audit readiness boundary: [`../architecture/real-runtime-audit-readiness-boundary.md`](../architecture/real-runtime-audit-readiness-boundary.md)
- container proxy topology boundary: [`../architecture/container-proxy-topologies.md`](../architecture/container-proxy-topologies.md)
