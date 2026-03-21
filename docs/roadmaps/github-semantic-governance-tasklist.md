# agent-auditor GitHub semantic governance tasklist

> Read-only roadmap mirror for the approved daemon tasklist in
> `.ralph/tasklists/github-semantic-governance-tasklist.locked.md`.
> Update task state through the daemon approval flow, not by editing this file by hand.

## Goal
- GitHub API の高リスク操作を semantic action として定義し、provider contract に沿って policy / audit / approval に流せるようにする

## Done when
- GitHub provider boundary が定義される
- 高リスク GitHub action taxonomy が定義される
- 公式 docs ベースで method / resource / permission / side effect が固定される
- GitHub action を `agenta-core` に正規化できる
- `agenta-policy` で GitHub action を評価できる
- approval / deny / hold を audit / approval record に反映できる
- 最低限の test / CI / runbook が揃う

## Scope
- in: GitHub provider boundary、high-risk action taxonomy、official docs ベースの metadata、policy bridge、audit / approval integration、tests、docs
- out: 全 GitHub API 網羅、production-grade GitHub mediation、full UI、non-GitHub provider

## Quality gates
- `cargo fmt --check`
- `cargo check`
- `cargo test`
- `cargo clippy -- -D warnings`

## Tasks
- [x] P9-1: GitHub provider boundary を定義し、provider metadata / action taxonomy / policy / record の責務を分離する
- [x] P9-2: high-risk GitHub action taxonomy を実装し、少なくとも `repos.update_visibility` / `branches.update_protection` / `actions.workflow_dispatch` / `actions.runs.rerun` / `pulls.merge` / `actions.secrets.create_or_update` を扱えるようにする
- [x] P9-3: 公式 docs ベースで method / resource / required permission / side effect を docs に固定する
- [ ] P9-4: GitHub action を `agenta-core` に正規化する
- [ ] P9-5: `agenta-policy` で GitHub action を評価できるようにする
- [ ] P9-6: approval / deny / hold を audit / approval record に反映する
- [ ] P9-7: GitHub semantic governance の unit test / smoke test を追加する
- [ ] P9-8: local runbook と既知制約を docs に残す
- [ ] P9-9: PR を分割作成し、CI green で main に取り込む
- [ ] P9-3-RECOVER: resolve runner block for task P9-3 (公式 docs ベースで method / resource / required permission / side effect を doc…): runner stderr と関連ログを確認し、詰まっているコード/設定を直してから再実行する (blocked: runner exit=Some(2): runner produced no stderr/stdout detail)
