# agent-auditor secret access model / broker MVP tasklist

Approved-By: n01e0
Approved-At: 2026-03-18T11:38:57.199213524+00:00

## Goal
- agent がどの secret に触れたかを追跡し、plaintext を残さずに policy 判定と audit 記録まで通す

## Done when
- secret file / mounted secret / brokered secret request を区別して扱える
- secret access event を `agenta-core` に正規化できる
- `agenta-policy` で secret policy を評価できる
- `allow / deny / require_approval` を secret event metadata と audit record に反映できる
- secret approval request と audit record の最小永続化がある
- 最低限の test / CI / runbook が揃う

## Scope
- in: secret taxonomy、secret access event model、mounted secret / secret file の識別、brokered secret request の最小モデル、policy bridge、audit / approval record、tests、docs
- out: 本格Vault実装、env var の完全追跡、browser / GWS secret flow、distributed secret service

## Quality gates
- `cargo fmt --check`
- `cargo check`
- `cargo test`
- `cargo clippy -- -D warnings`

## Tasks
- [x] P4-1: secret access MVP 境界を定義し、classify / evaluate / record の責務を分離する
- [x] P4-2: secret taxonomy を実装し、secret file / mounted secret / brokered secret request を識別できるようにする
- [ ] P4-3: secret access event を `agenta-core` に正規化する
- [ ] P4-4: secret policy を `agenta-policy` から評価できるようにする
- [ ] P4-5: `allow / deny / require_approval` を secret event metadata と audit record に反映する
- [ ] P4-6: secret approval request と audit record の最小永続化を追加する
- [ ] P4-7: secret access policy の unit test / smoke test を追加する
- [ ] P4-8: local runbook と既知制約を docs に残す
- [ ] P4-9: PR を分割作成し、CI green で main に取り込む
