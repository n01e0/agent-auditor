# agent-auditor

Linux 上で動く自律型エージェント向けの execution security / governance 基盤。

English version: [`README.md`](README.md)

`agent-auditor` は、権限を持つエージェントが何を見て、何を実行し、どの外部サービスや provider に対してどんな操作を行ったかを、Linux ホスト上と provider API の両面から観測・分類・監査・制御していくための Rust ワークスペース。

## 現在の状態

このリポジトリは **活発に開発中だが、まだ production-ready ではない**。

すでにあるもの:

- process exec/exit 観測 PoC
- filesystem governance PoC
- network destination governance PoC
- secret access のモデル化と approval/audit 経路
- deny / hold / approval の enforcement preview path
- Google Workspace semantic action モデル
- GitHub semantic action モデル
- generic REST / OAuth governance の基礎
- messaging / collaboration governance の基礎
- policy authoring / explainability の基礎
- productization / hardening の土台

まだ不足しているもの:

- production-grade な inline interception
- 磨かれた control plane / UI
- 安定した deployment packaging
- 長期互換性保証
- 外部 runtime との end-to-end integration の高信頼実装

別実機での現状の audit preview 目標は [`docs/architecture/preview-readiness-boundary.md`](docs/architecture/preview-readiness-boundary.md) を参照。
stand-in Compose smoke と OpenClaw / Hermes 実 runtime 確認の handoff-ready 境界は [`docs/architecture/real-runtime-audit-readiness-boundary.md`](docs/architecture/real-runtime-audit-readiness-boundary.md) を参照。
fixture preview / observed request / validated observation の境界は [`docs/architecture/real-traffic-observation-boundary.md`](docs/architecture/real-traffic-observation-boundary.md) を参照。
最終証跡を remote audit boundary 側に置く Hermes handoff は [`docs/runbooks/hermes-real-runtime-handoff-separate-trust-boundary.md`](docs/runbooks/hermes-real-runtime-handoff-separate-trust-boundary.md) を参照。

## リポジトリ構成

```text
agent-auditor/
  cmd/                バイナリ
  crates/             共有 Rust crate
  docs/               architecture / schema / runbook / roadmap
  examples/policies/  Rego policy のサンプル
  deploy/             deployment メモ（現状は最小限）
```

## バイナリ

現在の workspace バイナリ:

- `agent-auditor-hostd` — host 側 collector / enforcement preview daemon
- `agent-auditor-hostd-ebpf` — hostd PoC 用の eBPF object builder
- `agent-auditor-controld` — control-plane preview バイナリ
- `agent-auditor-cli` — ローカル診断 / 管理用 preview バイナリ

## インストール

現時点では developer 向けの導入が前提。

### 前提

- Linux
- Rust toolchain
- Rust/C 系の一般的なビルド環境

### clone

```bash
git clone git@github.com:n01e0/agent-auditor
cd agent-auditor
```

### build

```bash
cargo build
```

### ワークスペース全体の検証

```bash
cargo fmt --all --check
cargo check --workspace --all-targets
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
```

## クイックスタート

一番手早い入口は host daemon preview:

```bash
cargo run -p agent-auditor-hostd
```

ただし、これはまだ「本番用 daemon を live host 上で起動する」という意味ではない。現状は runbook に書かれた preview/bootstrap path を動かす形。

他の preview entrypoint:

```bash
cargo run -p agent-auditor-controld
cargo run -p agent-auditor-cli
```

### 別実機 audit preview の最小手順

別の Linux 実機で現状の preview を評価するなら、専用の最小セットアップ runbook を使う。

- [`docs/runbooks/separate-machine-audit-preview-local.md`](docs/runbooks/separate-machine-audit-preview-local.md)

この runbook で次をまとめて確認できる。

- 前提依存
- revision 固定の build
- `agent-auditor-hostd` / `agent-auditor-controld` の実行
- focused validation
- local JSONL / stdout inspection
- cleanup と retry

focused smoke test と runbook の対応表、それを踏まえた簡潔な checklist はここ。

- [`docs/runbooks/separate-machine-preview-checklist.md`](docs/runbooks/separate-machine-preview-checklist.md)

## 使い方

現状の `agent-auditor` は phase ごとに機能が積み上がっているので、使うときは次の順がわかりやすい。

1. architecture overview を読む
2. 見たい capability area を決める
3. 対応する runbook でローカル再現する
4. 対応する focused test を回す

おすすめの読み順:

1. [`docs/README.md`](docs/README.md)
2. [`docs/architecture/overview.md`](docs/architecture/overview.md)
3. 別実機で評価するなら [`docs/runbooks/separate-machine-audit-preview-local.md`](docs/runbooks/separate-machine-audit-preview-local.md)
4. 関連 runbook（[`docs/runbooks/README.md`](docs/runbooks/README.md)）
5. 深い architecture docs（[`docs/architecture/README.md`](docs/architecture/README.md)）

## 設定

今は **単一の安定した end-user 設定ファイル** はまだない。

設定面は大きく 3 層に分かれている。

### 1. Policy layer

Rego サンプルはここ:

- `examples/policies/sensitive_fs.rego`
- `examples/policies/process_exec.rego`
- `examples/policies/network_destination.rego`
- `examples/policies/secret_access.rego`
- `examples/policies/gws_action.rego`
- `examples/policies/github_action.rego`
- `examples/policies/generic_rest_action.rego`
- `examples/policies/messaging_action.rego`

### 2. Event / decision schema layer

契約はここ:

- `docs/schemas/event-envelope.schema.json`
- `docs/schemas/session.schema.json`
- `docs/schemas/approval-request.schema.json`
- `docs/schemas/policy-decision.schema.json`

### 3. Behavior / mode semantics layer

mode / coverage / known constraints はここ:

- `docs/architecture/`
- `docs/runbooks/`

## ドキュメント導線

まずここから:

- docs index: [`docs/README.md`](docs/README.md)

主要な入口:

- 要件定義: [`docs/PRD.md`](docs/PRD.md)
- architecture overview: [`docs/architecture/overview.md`](docs/architecture/overview.md)
- architecture index: [`docs/architecture/README.md`](docs/architecture/README.md)
- runbook index: [`docs/runbooks/README.md`](docs/runbooks/README.md)
- policy contract: [`docs/policies/rego-contract.md`](docs/policies/rego-contract.md)

## 開発フロー

普段のローカル検証はこれで十分。

```bash
cargo fmt --all --check
cargo check --workspace --all-targets
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
```

特定フェーズを触るときは、README 全体を読み直すより、対応する runbook と focused test を使うほうが早い。

## 現在の capability area

このリポジトリには、現時点で主に次の領域の architecture / runbook がある。

- runtime / host observation
- filesystem governance
- network destination governance
- secret access governance
- enforcement preview path
- Google Workspace semantic governance
- GitHub semantic governance
- generic REST / OAuth governance
- messaging / collaboration governance
- policy authoring / explainability
- productization / hardening gap

## 制約

いくつか重要な注意点:

- 多くの経路はまだ preview / PoC quality で、本番 enforcement ではない
- live hook が無い段階でも、将来の runtime 挙動を先に model 化している箇所がある
- 実装が phase ごとに増えてきたので、docs も phase-oriented になっている
- deployment guidance は architecture / testing material に比べるとまだ薄い

## 近い将来の方向性

直近は、新しい provider を広げる前に、既存機能の gap を埋めて productization hardening を進める方向。
