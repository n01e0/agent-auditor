# Runbook index

This directory contains local developer runbooks for reproducing the current PoCs and preview paths.

## Recommended starting points

- separate-machine audit preview: [`separate-machine-audit-preview-local.md`](separate-machine-audit-preview-local.md)
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
