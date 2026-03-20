# agent-auditor API / network GWS semantic action layer tasklist

> Read-only roadmap mirror for the approved daemon tasklist in
> `.ralph/tasklists/api-network-gws-semantic-action-layer-tasklist.locked.md`.
> Update task state through the daemon approval flow, not by editing this file by hand.

## Goal
- API / network 操作を session に紐づけ、Google Workspace 向け semantic action を公式 API ドキュメント準拠で policy / audit / approval に流せるようにする

## Done when
- API / network action event を session と関連付けて扱える
- GWS 向け semantic action を少なくとも 4 種定義できる
- semantic action を `agenta-core` に正規化できる
- `agenta-policy` で GWS semantic action policy を評価できる
- `allow / deny / require_approval` を event metadata と audit / approval record に反映できる
- 最低限の test / CI / runbook が揃う

## Scope
- in: API/network action session linkage、GWS semantic action taxonomy、official docs ベースの method/resource/scope 定義、policy bridge、audit / approval integration、tests、docs
- out: 任意サイト向け汎用 browser semantic parsing、production-grade browser instrumentation、full UI、non-GWS SaaS 全般

## Required references
- Google Drive API `permissions.update`
- Google Drive API `files.get`
- Gmail API `users.messages.send`
- Admin SDK Reports API `activities.list`

## Quality gates
- `cargo fmt --check`
- `cargo check`
- `cargo test`
- `cargo clippy -- -D warnings`

## Tasks
- [x] P6A-1: API/network GWS phase の境界を定義し、session linkage / classify / evaluate / record の責務を分離する（必要なら #46 の session linkage 部分を流用して browser-centric naming を修正する）
- [x] P6A-2: API / network action を session に紐づける最小 contract を実装する
- [x] P6A-3: GWS semantic action taxonomy を実装し、少なくとも `drive.permissions.update` / `drive.files.get_media` / `gmail.users.messages.send` / `admin.reports.activities.list` を扱えるようにする
- [x] P6A-4: semantic action ごとに公式 docs ベースで method / resource / side effect / OAuth scope を docs に固定する
- [ ] P6A-5: API/network GWS semantic action を `agenta-core` に正規化する
- [ ] P6A-6: GWS semantic action policy を `agenta-policy` から評価できるようにする
- [ ] P6A-7: `allow / deny / require_approval` を semantic action event metadata と audit / approval record に反映する
- [ ] P6A-8: API/network GWS semantic action の unit test / smoke test を追加する
- [ ] P6A-9: local runbook と既知制約を docs に残す
- [ ] P6A-10: PR を分割作成し、CI green で main に取り込む
- [ ] P6A-4-RECOVER: resolve runner block for task P6A-4 (semantic action ごとに公式 docs ベースで method / resource / side effect / OAuth …): runner stderr と関連ログを確認し、詰まっているコード/設定を直してから再実行する (blocked: runner exit=Some(2): runner produced no stderr/stdout detail)
