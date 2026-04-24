# axios Supply Chain Attack (2026-03-31)

> 個人研究メモ。Solo Purple Team手法による攻撃・防御両視点の分析。

---

##### Incident（インシデント概要）

**発生日**: 2026-03-31

**標的**: axios（npmで最も人気のHTTPクライアントライブラリ、週約1億DL）

**侵害されたバージョン**: axios@1.14.1, axios@0.30.4

**悪意ある依存パッケージ**: plain-crypto-js@4.2.1

**攻撃ベクトル**: postinstallスクリプト → RAT（遠隔操作型トロイの木馬）のダウンロード

**公開期間**: 約3時間（00:21〜03:15 UTC）

**帰属**: UNC1069 / Sapphire Sleet（北朝鮮関連脅威アクター）

**使用マルウェア**: WAVESHAPER.V2

##### Attack Chain（攻撃の流れ）
1. **Pre-staging（事前準備）**: 攻撃18時間前にplain-crypto-js@4.2.0（クリーン版）を公開
   - セキュリティスキャナーの「新規パッケージ」アラートを回避するOPSEC
2. **Initial Access（初期侵入）**: maintainer account compromise
   - ターゲット型ソーシャルエンジニアリング＋RATでメンテナーのPCに侵入
   - npmアカウント認証情報（jasonsaayman）を取得
   - メンテナーのメールアドレスをifstap@proton.meに変更
3. **Malicious Publish（悪意ある公開）**: 侵害アカウントからaxiosの悪意あるバージョンを公開
   - 39分以内に1.x・0.xの両ブランチを同時に汚染（影響範囲最大化）
4. **Dependency Injection（依存関係の注入）**: plain-crypto-js@4.2.1を依存関係に追加
   - axiosのソースコードにはimportされていない偽の依存パッケージ
5. **Execution Trigger（実行トリガー）**: 開発者が`npm install`を実行
   - 正常なインストール操作が悪意あるpostinstallスクリプトを起動
6. **RAT Download（RATのダウンロード）**
   - C2サーバー（sfrclak[.]com / 142.11.206[.]72:8000）からWAVESHAPER.V2を取得
   - OS別ペイロード: Windows（PowerShell）/ macOS（C++）/ Linux（Python）
7. **C2 Communication（C2通信の確立）**
   - 攻撃者のC2サーバーとの持続的な通信チャネルを確立
8. **Anti-Forensics（痕跡隠滅）**
   - マルウェアが自己削除し、package.jsonをクリーン版に差し替え
   - postinstallの実行痕跡をnode_modulesから消去

##### ATT&CK Mapping（MITRE ATT&CKフレームワークとの対応）
- **T1195.001** (Supply Chain Compromise: Compromise Software Dependencies)
  - サプライチェーン攻撃：ソフトウェア依存関係の侵害
- **T1059** (Command and Scripting Interpreter)
  - コマンド・スクリプトインタープリタの悪用
- **T1105** (Ingress Tool Transfer)
  - 外部からの攻撃ツール転送（マルウェアダウンロード）
- **T1071** (Application Layer Protocol)
  - アプリケーション層プロトコル（HTTPなどでC2通信）

##### Detection Hypothesis（検知仮説）
**H1: npm installからの異常なプロセス生成**
- 検知指標: `npm install` → nodeがshellプロセスを生成
- 根拠: 通常のnpm installでは対話型シェルは起動しない
- ログソース: Sysmon EventID 1（プロセス作成）
- 親子関係: npm.exe → node.exe → cmd.exe/powershell.exe

**H2: Node.jsからのPowerShell起動（高度に疑わしい）**
- 検知指標: node.exe → powershell.exe の実行
- 根拠: 通常の開発環境では極めて稀な挙動
- ログソース: Sysmon EventID 1、EDRプロセスツリー
- 文脈: パッケージインストール中にPowerShellが起動

**H3: インストール中の外部ネットワーク通信**
- 検知指標: npm install中に予期しない外部HTTP/HTTPS通信
- 根拠: パッケージインストールはnpmレジストリのみに接続すべき
- ログソース: ネットワークログ（Zeek、EDRネットワークテレメトリ）
- 正常な接続先: registry.npmjs.org
- 疑わしい接続先: sfrclak[.]com または 142.11.206[.]72:8000

**H4: package.jsonの自己書き換え検知（アンチフォレンジック対策）**
- 検知指標: node_modules内のpackage.jsonがインストール後に変更される
- 根拠: 通常のインストールではpackage.jsonは変更されない
- ログソース: ファイル整合性監視（FIM）/ Sysmon EventID 11（ファイル作成）

##### Pre-Lab Simulation（脅威モデリング）
**攻撃者視点（Red Team思考）**:
- Q1: どうやってnpmメンテナーアカウントに侵入するか?
  - ターゲット型ソーシャルエンジニアリング＋RATでPCに侵入し認証情報を窃取
- Q2: どのタイミングで悪意あるコードを注入するか?
  - 正規のアップデートサイクルに紛れ込ませる（通常の活動に偽装）

**防御者視点（Blue Team思考）**:
- Defense 1: package-lock.json差分検知
  - 依存関係の予期しない追加やバージョン変更を監視
- Defense 2: npm install時のネットワーク監視
  - 公式npmレジストリ以外への外部接続でアラート
- Defense 3: Sysmon EventID 1の監視
  - postinstallスクリプト実行中の異常なプロセス生成を検知
- Defense 4: FIMによるnode_modules監視
  - インストール後のpackage.json変更を検知（アンチフォレンジック対策）
