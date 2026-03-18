# agent-auditor network observe + destination policy tasklist

Approved-By: n01e0
Approved-At: 2026-03-18T06:29:24.979767123+00:00

## Goal
- Linux/container 上の agent の outbound 通信を観測し、宛先ベースの policy 判定と audit 記録まで通す

## Done when
- outbound connect event を hostd で観測できる
- destination IP / port / protocol を `agenta-core` に正規化できる
- domain attribution の最小戦略があり、制約が docs に残る
- `agenta-policy` 経由で destination policy を評価できる
- `allow / deny / require_approval` を network event metadata と audit record に反映できる
- 最低限の test / CI / runbook が揃う

## Scope
- in: eBPF ベースの outbound observe、destination classification、policy bridge、audit record、tests、docs
- out: full L7 parsing、browser / GWS、distributed enforcement、k8s production hardening、full UI

## Quality gates
- `cargo fmt --check`
- `cargo check`
- `cargo test`
- `cargo clippy -- -D warnings`

## Tasks
- [x] P3-1: network PoC 境界を定義し、observe / classify / emit の責務を分離する
- [x] P3-2: outbound connect event を hostd で取得し、最小ログ出力まで通す
- [x] P3-3: destination IP / port / protocol を `agenta-core` に正規化する
- [x] P3-4: domain attribution の最小戦略を実装し、制約を明文化する
- [x] P3-5: destination policy を `agenta-policy` から評価できるようにする
- [x] P3-6: `allow / deny / require_approval` を network event metadata と audit record に反映する
- [x] P3-7: network observe + policy の unit test / smoke test を追加する
- [ ] P3-8: local runbook と既知制約を docs に残す
- [ ] P3-9: PR を分割作成し、CI green で main に取り込む
