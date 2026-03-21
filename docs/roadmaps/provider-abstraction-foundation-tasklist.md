# agent-auditor provider abstraction foundation tasklist

This roadmap mirrors the daemon-owned source of truth at
`.ralph/tasklists/provider-abstraction-foundation-tasklist.locked.md`.

## Goal

- GWS 固有の semantic action model を provider 共通の contract に一般化し、次の provider を壊さず追加できる基盤を作る

## Done when

- provider 共通の semantic action contract がある
- GWS 実装がその contract に載る
- provider metadata / method / resource / side effect / scope を共通 schema で表現できる
- `agenta-policy` が provider + action ベースで自然に評価できる
- GitHub を次の provider として追加できる土台が docs / types / tests 上で示せる
- 最低限の test / CI / runbook が揃う

## Scope

- in: provider 共通 contract、provider metadata model、policy input 一般化、GWS 実装の載せ替え、GitHub 追加を見据えた schema / docs / tests
- out: GitHub provider の本格実装、non-GitHub provider 全般の本実装、full UI、distributed control plane

## Quality gates

- `cargo fmt --check`
- `cargo check`
- `cargo test`
- `cargo clippy -- -D warnings`

## Tasks

- [ ] P8-1: provider abstraction phase の境界を定義し、provider contract / provider metadata / provider-specific action taxonomy の責務を分離する
- [ ] P8-2: provider 共通 semantic action contract を `agenta-core` に追加する
- [ ] P8-3: method / resource / side effect / OAuth scope / privilege class を provider 共通 metadata として表現できるようにする
- [ ] P8-4: GWS semantic action 実装を provider abstraction contract に載せ替える
- [ ] P8-5: `agenta-policy` の入力を provider + action ベースに一般化する
- [ ] P8-6: GitHub provider を次段で追加できるように、候補 action と metadata shape を docs に固定する
- [ ] P8-7: provider abstraction の unit test / smoke test を追加する
- [ ] P8-8: local runbook と既知制約を docs に残す
- [ ] P8-9: PR を分割作成し、CI green で main に取り込む
