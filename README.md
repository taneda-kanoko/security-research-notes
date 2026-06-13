# security-research-notes

インフラエンジニア（3年目）として実務を行いながら、セキュリティエンジニアへのキャリア転換に向けて個人研究を進めています。  
MITRE ATT&CK フレームワークに基づき、攻撃・防御両面からの分析を記録しています。

---

## 研究方針：Solo Purple Team Protocol

実際の攻撃事例を題材に、攻撃者・防御者の両視点を順番に経由して分析します。

Phase A │ 攻撃者視点  ── どのように侵入・実行・隠蔽するか

Phase B │ インターバル ── 10分。視点をリセットする

Phase C │ 防御者視点  ── どのログが出るか・どう検知できるか

Phase D │ 反事実分析  ── もし攻撃者が〇〇だったら何が変わるか

各メモは以下の構成で記述しています：  
`Incident概要` → `Attack Chain` → `ATT&CK Mapping` → `Detection Hypothesis` → `Pre-Lab Simulation`

---

## 研究メモ

### 脆弱性分析 / Vulnerability Analysis

> **エッジデバイスの認証バイパスを中心に分析。**  
> CISA KEV 登録済みの実悪用脆弱性を対象に、攻撃メカニズムの理解・検知仮説の構築・予測精度の振り返りを記録しています。

| ファイル | 対象インシデント | 主要テクニック |
|---|---|---|
| [PAN-OS GlobalProtect 認証バイパス分析（2026-06）](./vulnerability-analysis/panos-globalprotect-auth-bypass-2026.md) | CVE-2026-0257: Cookie偽造によるVPN不正接続（CISA KEV登録） | T1190, T1078 |

---

### サプライチェーン攻撃 / Supply Chain

> **2026年3月31日〜4月1日の連続インシデント分析。**  
> axios アカウント侵害（3/31）と、その翌日に発生した Claude Code ソース漏洩に乗じたスクワッティング攻撃（4/1）を連鎖として分析しています。  
> 同一の npm エコシステムを標的とし、手法・OPSEC レベルが対照的な2件を比較することで、サプライチェーン攻撃の戦術バリエーションを整理しました。

| ファイル | 対象インシデント | 主要テクニック |
|---|---|---|
| [axios サプライチェーン攻撃分析（2026-03）](./supply-chain/axios-supply-chain-attack-2026.md) | axios npm パッケージ汚染（UNC1069 / Sapphire Sleet） | T1195.001, T1059, T1105 |
| [Claude Code npm スクワッティング分析 Run 1（2026-04）](./supply-chain/claude-code-npm-squatting-2026.md) | ソース漏洩に乗じた Dependency Confusion 攻撃 | T1195.001, T1036.005, T1608.001 |
| [npm スクワッティング Run 2: SBOM 検証（2026-06）](./supply-chain/npm-squatting-sbom-detection-2026.md) | Run 1 の課題（1ビット前提条件問題）を SBOM で解消 | T1195.001, T1195.002 |

**2件の比較サマリー：**

| 項目 | axios 攻撃（3/31） | Claude Code スクワッティング（4/1） |
|---|---|---|
| 攻撃タイプ | アカウント侵害 → 既存パッケージ改ざん | Typosquatting → 新規パッケージ登録 |
| 即時危険度 | 高（RAT を即座に配布） | 低（空スタブ、将来の悪用を待機） |
| OPSEC レベル | 低（短時間・即露見） | 高（段階的・長期待機型） |
| 検知難易度 | 中 | 高（正常な新規パッケージに見える） |

**研究の発展：**

| フェーズ | 日付 | 主な発見 |
|---|---|---|
| [axios 攻撃分析](./supply-chain/axios-supply-chain-attack-2026.md) | 2026-03-31 | Sysmon プロセスチェーン検知（H1/H3 成功・H2 ログ欠損で失敗） |
| [npm スクワッティング Run 1](./supply-chain/claude-code-npm-squatting-2026.md) | 2026-04-01 | 1ビット前提条件問題——情報優位の有無が検知率 100% と 0% を分断 |
| [npm スクワッティング Run 2](./supply-chain/npm-squatting-sbom-detection-2026.md) | 2026-06-04 | SBOM = 最小検知条件——インシデント依存の検知から予防的検知へ転換 |

---

## 個人研究システム

脅威インテリジェンスの収集・分析・検索・仮説検証を支援する統合プラットフォームをローカル環境で自作・運用しています。
外部APIに依存せず、ローカルLLM + SQLiteで完全にオフライン動作します。

### 技術スタック

| レイヤー | 技術 |
|---------|------|
| 言語 | Python 3.12 |
| LLM | Ollama (ローカル実行) — APIコスト0 |
| DB | SQLite |
| API | Flask |
| 脅威データ | CISA KEV, NVD CVE API, GitHub Advisory |
| フレームワーク | MITRE ATT&CK |
| 通知 | Slack Webhook |
| ナレッジ管理 | Obsidian (Markdown) |

### 設計思想

- **ゼロコスト運用**：外部API課金なし。LLMもローカル実行
- **セキュリティファースト**：機密データが外部に出ない。完全オフライン動作可能
- **Purple Team統合**：Blue Team（検知）とRed Team（攻撃技術）の両方を自動収集・分類
- **実用性重視**：毎朝Slackに自動配信。日常のワークフローに組み込み済み

---

## 資格・学習状況

| 資格 | 状況 |
|---|---|
| SC-900 (Microsoft Security Fundamentals) | ✅ 2026年4月取得 |
| 応用情報技術者試験 | 🔄 2026年11月受験予定 |
| 情報処理安全確保支援士 | 🔄 2027年2月受験予定 |

---

## 研究ロードマップ

| Phase | 内容 |
|-------|------|
| Phase 1（現在） | 情報収集・仮説検証・Solo Purple Team演習（仮想環境） |
| Phase 2 | 支援士取得・Security+ / SC-200 取得 |
| Phase 3 | Proxmox Cyber Range 構築（実環境演習へ） |
| Phase 4 | CEH → OSCP 取得 |
| Phase 5 | パープルチームリード |

---

## 免責事項

本リポジトリに記載する情報はすべて**公開情報のみ**を使用し、防御目的での分析を目的としています。  
実際の攻撃への転用や、外部システムへの不正アクセスは一切行っていません。
