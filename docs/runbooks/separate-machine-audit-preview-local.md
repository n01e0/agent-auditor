# separate-machine audit preview: local runbook

This runbook fixes the **minimum separate-machine setup path** for evaluating the current `agent-auditor` audit preview on another Linux host.

It is the smallest honest path for:

- dependencies / prerequisites
- revision-pinned build
- running the checked-in preview binaries
- validating the checked-in preview contract
- inspecting bootstrap-local JSONL artifacts
- cleaning up preview state before retrying or switching revisions

Use this runbook when the question is:

> can another Linux machine reproduce the current preview without reverse-engineering the repository?

This is an **audit preview** runbook, not a production deployment guide.

## what this path currently proves

Following this runbook proves only that another Linux machine can:

- build the checked-in revision
- run `agent-auditor-hostd` and `agent-auditor-controld` bootstrap previews
- run the focused smoke checks that back the current preview contract
- inspect the resulting local JSONL artifacts and stdout previews
- clean up preview state and retry from the same revision or a known-good revision

It does **not** prove:

- production daemonization
- container/systemd packaging
- live inline enforcement on external traffic
- durable multi-host control-plane state
- production rollback orchestration

## 1. dependencies / prerequisites

On the separate Linux machine, make sure you have:

- `git`
- a Rust toolchain new enough for the workspace (`Cargo.toml` currently pins Rust `1.93`)
- a normal Rust/C build environment that can run `cargo build` and `cargo test`
- optional but strongly recommended local inspection helpers:
  - `rg`
  - `jq`

The current minimum path assumes a developer-style Linux environment. It does **not** require root for the checked-in preview/bootstrap flow.

## 2. check out an exact revision

Do not evaluate from an uncommitted tree.

```bash
git clone git@github.com:n01e0/agent-auditor
cd agent-auditor
git checkout <exact-commit-or-tag>
```

Current rule:

- binaries, docs, and expectations should come from the same revision
- if the revision changes, rebuild and rerun the preview from that revision instead of mixing outputs

## 3. build the minimum preview binaries

From the repository root:

```bash
cargo build --release -p agent-auditor-hostd -p agent-auditor-controld -p agent-auditor-cli
```

This is the current minimum packageable unit for the separate-machine preview:

- `target/release/agent-auditor-hostd`
- `target/release/agent-auditor-controld`
- `target/release/agent-auditor-cli`

## 4. run the checked-in preview entrypoints

### host-side preview

```bash
./target/release/agent-auditor-hostd | tee /tmp/agent-auditor-hostd.preview.log
```

Expected bootstrap output includes hostd preview lines plus persisted preview artifacts under `target/`.

### control-plane preview

```bash
./target/release/agent-auditor-controld | tee /tmp/agent-auditor-controld.preview.log
```

The current `agent-auditor-controld` path is stdout-only. It does not create a durable local queue database.

### optional local diagnostics binary

```bash
./target/release/agent-auditor-cli --help
```

The CLI is not the primary preview gate, but building it proves the currently documented operator-facing binary set still compiles from the same revision.

## 5. run the minimum focused validation

For the separate-machine preview target, this is the smallest honest validation set:

```bash
cargo test -p agent-auditor-hostd --test poc_smoke
cargo test -p agent-auditor-hostd --test live_proxy_seam_smoke
cargo test -p agent-auditor-controld --test control_plane_smoke
```

If you are qualifying a candidate revision more broadly, run the full workspace baseline too:

```bash
cargo fmt --all --check
cargo check --workspace --all-targets
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
```

## 6. inspect the bootstrap-local artifacts

After `agent-auditor-hostd` runs, start by listing the preview artifact directories:

```bash
find target -maxdepth 1 -type d -name 'agent-auditor-hostd*-store' | sort
```

The current preview writes JSONL artifacts under directories such as:

- `target/agent-auditor-hostd-poc-store/`
- `target/agent-auditor-hostd-secret-poc-store/`
- `target/agent-auditor-hostd-network-poc-store/`
- `target/agent-auditor-hostd-gws-poc-store/`
- `target/agent-auditor-hostd-github-poc-store/`
- `target/agent-auditor-hostd-generic-rest-poc-store/`
- `target/agent-auditor-hostd-messaging-poc-store/`

Common files include:

- `audit-records.jsonl`
- `approval-requests.jsonl`

Quick inspection examples:

```bash
jq -c . target/agent-auditor-hostd-messaging-poc-store/approval-requests.jsonl
jq -c . target/agent-auditor-hostd-gws-poc-store/audit-records.jsonl
```

For the checked-in minimal local inspection view, compare:

```bash
cargo run -p agent-auditor-hostd --quiet | rg '^approval_local_jsonl_inspection_model=|^persisted_messaging_local_jsonl_inspection_require_approval='
cargo run -p agent-auditor-controld --quiet | rg '^approval_audit_export_pending_review=|^approval_audit_export_waiting_merge=|^approval_audit_export_resolved='
```

Use these runbooks when you want deeper inspection:

- control-plane export view: [`approval-control-plane-ux-local.md`](approval-control-plane-ux-local.md)
- local approval JSONL inspection: [`approval-jsonl-inspection-local.md`](approval-jsonl-inspection-local.md)
- GWS preview artifacts: [`hostd-api-network-gws-poc-local.md`](hostd-api-network-gws-poc-local.md)
- messaging preview artifacts: [`messaging-collaboration-governance-local.md`](messaging-collaboration-governance-local.md)

## 7. retry / rollback rule

If the second machine does **not** reproduce the expected preview output:

1. stop trusting the candidate revision
2. clean the preview-local artifact directories
3. rerun the focused validation from the same revision
4. if the mismatch remains, switch back to the last known-good revision and rebuild from that revision

Current rollback unit:

- the repository revision

Current retry unit:

- the repository revision plus a clean preview-local `target/agent-auditor-hostd*-store` state

## 8. cleanup

To clean up the current separate-machine preview state:

```bash
rm -f /tmp/agent-auditor-hostd.preview.log /tmp/agent-auditor-controld.preview.log
rm -rf \
  target/agent-auditor-hostd-poc-store \
  target/agent-auditor-hostd-secret-poc-store \
  target/agent-auditor-hostd-network-poc-store \
  target/agent-auditor-hostd-gws-poc-store \
  target/agent-auditor-hostd-github-poc-store \
  target/agent-auditor-hostd-generic-rest-poc-store \
  target/agent-auditor-hostd-messaging-poc-store
```

You do **not** need to delete the whole repository clone unless you want a fully fresh checkout.

## shortest honest checklist

If you only want the minimum separate-machine preview checklist, use this order:

1. `git checkout <exact revision>`
2. `cargo build --release -p agent-auditor-hostd -p agent-auditor-controld -p agent-auditor-cli`
3. `./target/release/agent-auditor-hostd`
4. `./target/release/agent-auditor-controld`
5. `cargo test -p agent-auditor-hostd --test poc_smoke`
6. `cargo test -p agent-auditor-hostd --test live_proxy_seam_smoke`
7. `cargo test -p agent-auditor-controld --test control_plane_smoke`
8. inspect `target/agent-auditor-hostd*-store/`
9. clean the preview-local stores before retrying another revision

## related docs

- [`../architecture/preview-readiness-boundary.md`](../architecture/preview-readiness-boundary.md)
- [`../architecture/preview-readiness-gap-matrix.md`](../architecture/preview-readiness-gap-matrix.md)
- [`../architecture/deployment-hardening-minimums.md`](../architecture/deployment-hardening-minimums.md)
- [`approval-control-plane-ux-local.md`](approval-control-plane-ux-local.md)
- [`approval-jsonl-inspection-local.md`](approval-jsonl-inspection-local.md)
