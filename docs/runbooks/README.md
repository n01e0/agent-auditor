# Runbook index

This directory contains local developer runbooks for reproducing the current PoCs and preview paths.

Most runbooks are still preview-first. For the current repository-wide boundary between `fixture preview`, `observed request`, and `validated observation`, cross-check [`../architecture/real-traffic-observation-boundary.md`](../architecture/real-traffic-observation-boundary.md) and the operator checklist in [`separate-machine-preview-checklist.md`](separate-machine-preview-checklist.md) before reading any single runbook as a blanket real-traffic claim.

## Recommended starting points

- separate-machine audit preview: [`separate-machine-audit-preview-local.md`](separate-machine-audit-preview-local.md)
- separate-machine preview checklist: [`separate-machine-preview-checklist.md`](separate-machine-preview-checklist.md)
- real-runtime proxy trust bootstrap (dev minimum): [`real-runtime-proxy-trust-bootstrap-dev.md`](real-runtime-proxy-trust-bootstrap-dev.md)
- real-runtime audit inspection (observed-runtime path + audit/local inspection): [`real-runtime-audit-inspection-local.md`](real-runtime-audit-inspection-local.md)
- runtime process observation: [`hostd-exec-exit-poc-local.md`](hostd-exec-exit-poc-local.md)
- filesystem governance: [`hostd-filesystem-poc-local.md`](hostd-filesystem-poc-local.md)
- network governance: [`hostd-network-poc-local.md`](hostd-network-poc-local.md)
- secret access governance: [`hostd-secret-access-poc-local.md`](hostd-secret-access-poc-local.md)
- enforcement preview path: [`hostd-enforcement-foundation-local.md`](hostd-enforcement-foundation-local.md)

## Provider / API governance runbooks

- API/network GWS governance: [`hostd-api-network-gws-poc-local.md`](hostd-api-network-gws-poc-local.md)
- GitHub semantic governance: [`hostd-github-semantic-governance-poc-local.md`](hostd-github-semantic-governance-poc-local.md)
- generic REST / OAuth governance: [`generic-rest-oauth-governance-local.md`](generic-rest-oauth-governance-local.md)
- messaging / collaboration governance: [`messaging-collaboration-governance-local.md`](messaging-collaboration-governance-local.md)

## Control plane / explainability runbooks

- approval / control-plane UX: [`approval-control-plane-ux-local.md`](approval-control-plane-ux-local.md)
- approval JSONL inspection: [`approval-jsonl-inspection-local.md`](approval-jsonl-inspection-local.md)
- policy authoring / explainability: [`policy-authoring-explainability-local.md`](policy-authoring-explainability-local.md)
- provider abstraction foundation: [`provider-abstraction-foundation-local.md`](provider-abstraction-foundation-local.md)

## How to use these runbooks

1. start from the repository root
2. run the baseline validation commands listed in the runbook
3. run the focused tests or `cargo run` examples for the slice you care about
4. cross-check the matching architecture and known-constraints docs under [`../architecture/`](../architecture/README.md)

Most runbooks describe preview or PoC behavior, not production deployment.
