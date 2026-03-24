# Architecture index

This directory contains design notes for the current `agent-auditor` architecture.

## Core documents

- overview: [`overview.md`](overview.md)
- coverage matrix: [`coverage-matrix.md`](coverage-matrix.md)
- Rust implementation direction: [`rust-implementation.md`](rust-implementation.md)
- failure behavior: [`failure-behavior.md`](failure-behavior.md)
- deployment hardening minimums: [`deployment-hardening-minimums.md`](deployment-hardening-minimums.md)

## Runtime / host foundations

- exec / exit PoC: [`hostd-exec-exit-poc.md`](hostd-exec-exit-poc.md)
- filesystem PoC: [`hostd-filesystem-poc.md`](hostd-filesystem-poc.md)
- network PoC: [`hostd-network-poc.md`](hostd-network-poc.md)
- network domain attribution: [`hostd-network-domain-attribution.md`](hostd-network-domain-attribution.md)
- secret access PoC: [`hostd-secret-access-poc.md`](hostd-secret-access-poc.md)
- enforcement foundation: [`hostd-enforcement-foundation.md`](hostd-enforcement-foundation.md)
- process enforcement preview: [`hostd-process-enforcement-poc.md`](hostd-process-enforcement-poc.md)

## Provider / API governance

- API/network GWS foundation: [`hostd-api-network-gws-poc.md`](hostd-api-network-gws-poc.md)
- API/network GWS action catalog: [`hostd-api-network-gws-action-catalog.md`](hostd-api-network-gws-action-catalog.md)
- GitHub semantic governance: [`hostd-github-semantic-governance-poc.md`](hostd-github-semantic-governance-poc.md)
- generic REST / OAuth foundation: [`generic-rest-oauth-governance-foundation.md`](generic-rest-oauth-governance-foundation.md)
- messaging / collaboration foundation: [`messaging-collaboration-governance-foundation.md`](messaging-collaboration-governance-foundation.md)
- messaging / collaboration catalog: [`messaging-collaboration-action-catalog.md`](messaging-collaboration-action-catalog.md)
- provider abstraction foundation: [`provider-abstraction-foundation.md`](provider-abstraction-foundation.md)
- provider GitHub candidate catalog: [`provider-abstraction-github-candidate-catalog.md`](provider-abstraction-github-candidate-catalog.md)

## Live preview / proxy seam

- live proxy interception foundation: [`live-proxy-interception-foundation.md`](live-proxy-interception-foundation.md)
- live proxy HTTP request contract: [`live-proxy-http-request-contract.md`](live-proxy-http-request-contract.md)
- generic live action envelope: [`generic-live-action-envelope.md`](generic-live-action-envelope.md)
- provider live preview adapter boundaries: [`provider-live-preview-adapter-boundaries.md`](provider-live-preview-adapter-boundaries.md)
- generic REST live preview path: [`generic-rest-live-preview-path.md`](generic-rest-live-preview-path.md)
- live preview mode semantics: [`live-preview-mode-semantics.md`](live-preview-mode-semantics.md)
- live preview record reflection: [`live-preview-record-reflection.md`](live-preview-record-reflection.md)
- live preview coverage visibility: [`live-preview-coverage-visibility.md`](live-preview-coverage-visibility.md)
- live proxy coverage matrix: [`live-proxy-coverage-matrix.md`](live-proxy-coverage-matrix.md)
- live proxy test fixtures: [`live-proxy-test-fixtures.md`](live-proxy-test-fixtures.md)

## Approval / control plane / explainability

- approval/control-plane UX foundation: [`approval-control-plane-ux-foundation.md`](approval-control-plane-ux-foundation.md)
- approval/control-plane minimal model: [`approval-control-plane-ux-minimal-model.md`](approval-control-plane-ux-minimal-model.md)
- approval/control-plane status explanation: [`approval-control-plane-status-explanation.md`](approval-control-plane-status-explanation.md)
- approval/control-plane notification/reconciliation: [`approval-control-plane-status-notification-reconciliation.md`](approval-control-plane-status-notification-reconciliation.md)
- approval/control-plane audit export: [`approval-control-plane-audit-export.md`](approval-control-plane-audit-export.md)
- approval/control-plane ops hardening: [`approval-control-plane-ops-hardening.md`](approval-control-plane-ops-hardening.md)
- policy authoring / explainability foundation: [`policy-authoring-explainability-foundation.md`](policy-authoring-explainability-foundation.md)
- policy authoring model v1: [`policy-authoring-model-v1.md`](policy-authoring-model-v1.md)
- policy explanation schema v1: [`policy-explanation-schema-v1.md`](policy-explanation-schema-v1.md)

## Gap-closing / hardening

- gap-closing foundation: [`gap-closing-productization-hardening-foundation.md`](gap-closing-productization-hardening-foundation.md)
- gap matrix: [`gap-closing-gap-matrix.md`](gap-closing-gap-matrix.md)

## Known constraints

Constraint docs are intentionally split per area. The most useful entrypoints are:

- enforcement constraints: [`hostd-enforcement-known-constraints.md`](hostd-enforcement-known-constraints.md)
- filesystem constraints: [`hostd-filesystem-known-constraints.md`](hostd-filesystem-known-constraints.md)
- network constraints: [`hostd-network-known-constraints.md`](hostd-network-known-constraints.md)
- secret access constraints: [`hostd-secret-access-known-constraints.md`](hostd-secret-access-known-constraints.md)
- API/network GWS constraints: [`hostd-api-network-gws-known-constraints.md`](hostd-api-network-gws-known-constraints.md)
- GitHub semantic governance constraints: [`hostd-github-semantic-governance-known-constraints.md`](hostd-github-semantic-governance-known-constraints.md)
- generic REST / OAuth constraints: [`generic-rest-oauth-governance-known-constraints.md`](generic-rest-oauth-governance-known-constraints.md)
- messaging / collaboration constraints: [`messaging-collaboration-governance-known-constraints.md`](messaging-collaboration-governance-known-constraints.md)
- provider abstraction constraints: [`provider-abstraction-known-constraints.md`](provider-abstraction-known-constraints.md)
- policy authoring / explainability constraints: [`policy-authoring-explainability-known-constraints.md`](policy-authoring-explainability-known-constraints.md)
- approval/control-plane UX constraints: [`approval-control-plane-ux-known-constraints.md`](approval-control-plane-ux-known-constraints.md)
