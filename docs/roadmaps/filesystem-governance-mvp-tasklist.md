# agent-auditor filesystem governance MVP tasklist

## Goal
- sensitive filesystem access を Linux/container 上で観測し、policy 判定と audit 記録まで通す

## Done when
- hostd で sensitive path read/write を観測できる
- filesystem access event を `agenta-core` の型へ正規化できる
- `agenta-policy` 経由で Rego の `allow / deny / require_approval` を返せる
- policy 判定結果を audit event metadata に反映できる
- approval request record と audit record の最小永続化がある
- 最低限のテストと CI が green
- ローカル実行手順と既知制約が repo に残る

## Scope
- in: `fanotify` ベースの filesystem observe、sensitive path classification、Rego 判定接続、audit/approval の最小永続化、tests、docs
- out: browser / GWS、network egress policy、本格 process deny、multi-node / k8s 最適化、full UI

## Quality gates
- `cargo fmt --check`
- `cargo check`
- `cargo test`
- `cargo clippy -- -D warnings`

## Tasks
- [x] P2-1: `fanotify` 前提の filesystem PoC 境界を定義し、watch / classify / emit の責務を分離する
- [x] P2-2: sensitive path classifier を実装し、`.ssh` / `.env` / mounted secrets を暫定対象として扱えるようにする
- [ ] P2-3: filesystem access event を `agenta-core` に正規化して出力する
- [ ] P2-4: `agenta-policy` から Rego 判定を呼ぶ最小経路を実装する
- [ ] P2-5: `allow / deny / require_approval` の判定結果を event metadata に反映する
- [ ] P2-6: approval request record と audit record の最小永続化を追加する
- [ ] P2-7: fanotify + policy の unit test / smoke test を追加する
- [ ] P2-8: local runbook と既知制約を docs に残す
- [ ] P2-9: PR を分割作成し、CI green で main に取り込む
