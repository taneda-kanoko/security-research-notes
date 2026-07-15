# Splunk Pre-Auth RCE and Monitoring System Redundancy (CVE-2026-20253)

> 個人研究メモ。Solo Purple Team手法による攻撃・防御両視点の分析。

---

##### Incident（インシデント概要）

- **CVE**: CVE-2026-20253
- **CVSS**: 9.8 (Critical) / `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
- **CWE**: CWE-306（重要な機能に対する認証の欠如）
- **影響製品**: Splunk Enterprise 10.0.0-10.0.6 / 10.2.0-10.2.3
- **非影響**: 9.4以前 / 10.4 / Splunk Cloud（PostgreSQL sidecar不使用）
- **脆弱性条件**:
  - PostgreSQL Sidecar Service 有効
  - AWS版はデフォルト有効（out-of-the-box で脆弱）、オンプレは手動有効化時のみ
- **修正版**: 10.0.7 / 10.2.4 / 10.4.0 以上
- **タイムライン**:
  - 2026-06-10: Splunk がアドバイザリ（SVD-2026-0603）公開、PSIRTが限定的な悪用を認知
  - 2026-06-12: 第三者による技術解析公開
  - 2026-06-19: 実悪用継続の報道
  - CISA KEV 登録済み（連邦機関の対処期限: 2026-06-21）

##### Attack Mechanism（攻撃メカニズム）

1. 攻撃者が Splunk Web (8000番) の未認証エンドポイントへ到達
2. sidecar の recovery 用エンドポイント（backup / restore）を呼ぶ
3. database パラメータに PostgreSQL 接続文字列を注入し、接続先を上書き
4. 攻撃者制御の DB へ接続し、認証情報の奪取や悪性 SQL の実行を行う
5. 悪性 SQL 経由で Splunk プロセスへ RCE 到達

**根本原因**:

- sidecar エンドポイントに認証制御が欠落している（CWE-306）
- Authorization ヘッダはパースされるが検証されず、認証判断がローカル PostgreSQL に委譲される
- アプリケーション層での認証チェックが存在しない

##### ATT&CK Mapping

* **T1190** (Exploit Public-Facing Application): 未認証エンドポイントへの到達と接続文字列注入
* **T1059** (Command and Scripting Interpreter): 悪性 SQL 経由での Splunk プロセスへのコード実行到達
* **T1562** (Impair Defenses): 監視ツール自体の侵害・ログ改ざんの可能性

##### Detection Hypothesis（検知仮説）

**H1: Detection outside Splunk succeeds only when the alert path itself is independent of Splunk**

- 観測点で観察できる検知指標:
  - Unauthenticated HTTP 200 responses to the PostgreSQL recovery endpoints
  - PostgreSQL connection-string parameters (hostaddr / passfile) appearing in HTTP request bodies
  - Outbound TCP connections to port 5432 originating from Splunk hosts
- 根拠: 攻撃 (1)〜(3) は Splunk 前段の通信経路を通過するため、Splunk 外の観測点で観測可能
- ログソース: WAF（未認証200応答パターン）／ NetFlow（外向き5432通信）／ FW（通信ポリシー違反）

**成立条件（アラート経路の独立性）**:

- Alerts from these observation points must not flow into the same Splunk instance that could be compromised
- Independent notification channels (email, external services, secondary SIEM) are required to preserve detection results after Splunk compromise

**検知が困難なシグナル**:

- 攻撃 (5) の RCE 到達は Splunk ホスト内部の挙動であり、侵害後はログ改ざんで隠蔽され得る
- 内部プロキシ経由や正規に見える接続先を使った外向き通信の偽装

##### Defense（防御・緩和策）

- **即時**: Splunk Enterprise 10.0.7 / 10.2.4 / 10.4.0 以上へアップグレード
- **暫定緩和**: `server.conf` に `[postgres] disabled = true` を追加
  （副作用: Edge Processor / OpAmp / SPL2 pipeline が停止）
- **構造的**:
  - Splunk 外の観測点（WAF / NetFlow / FW）を持つ
  - アラート通知経路を Splunk に集約しない（メール・Slack 等の独立チャネルへ）
  - ログ保存先を多重化する（WORM ストレージ・オブジェクトストレージ複製）

##### Pre-Lab Simulation（脅威モデリング）

**攻撃者視点（Red Team思考）**:

* CVE-2026-20253 は認証を必要としないため、Splunk Web に到達できる位置から即座に悪用可能
* 攻撃者 DB への接続時に生じる外向き 5432 通信は、防御側で最も観察されやすい痕跡
* 内部プロキシ経由の偽装や、正規に見える接続先の利用で検知回避を試みる余地がある

**防御者視点（Blue Team思考）**:

* Splunk 前段の観測点（WAF / NetFlow / FW）で HTTP 層と通信層を独立して監視する
* 未認証での 200 応答パターンを WAF の検知シグナルとして設定する
* 想定外の外向き 5432 通信を FW / NetFlow で監視する
* **重要**: 検知結果が Splunk に集約される設計だと、Splunk 侵害後にアラートが失われる可能性がある

##### Lessons Learned（教訓）

**監視システム自身が標的になると「関係ベースの検知」が成立しない（構造的転換）**:

過去の研究（axios, npm squatting, LOLBins, PAN-OS）は「正規な要素、異常な関係」を検知の手がかりにできた。だが CVE-2026-20253 では観測者（Splunk）自身が侵害され得る。関係を見る主体が信頼できない以上、Splunk 内観測だけでは検知が成立しない。

**設計原則：Observer redundancy（監視系冗長化）**:

検知を単一の監視システムに依存させず、観測点・通知経路・ログ保存の3層をすべて独立させる。WAF を足しても、そのアラートが同じ Splunk に集約されるなら無意味。独立性は3層すべてに及ぶ必要がある。

##### Prediction Accuracy（予測精度の振り返り）

- **初期予測**: 接続文字列注入（攻撃 (2)）が最も検知されやすい痕跡になると予測
- **実際**: PARTIAL / Partially Validated
- **主な誤差要因**: HTTP ペイロード上の接続文字列（(2)）は WAF 層の有効な信号だが難読化の余地がある。より頑健で改ざん耐性のある信号は、攻撃 (3) の外向き 5432 通信だった。さらに、検知の成否は「アラート経路が Splunk から独立しているか」に依存するという条件が、当初の予測に含まれていなかった。

##### ATT&CK Reference

- T1190, T1059, T1562
- CISA KEV 登録済み
- 一次情報: Splunk Advisory SVD-2026-0603
- 関連CVE: なし（新規テーマ）
