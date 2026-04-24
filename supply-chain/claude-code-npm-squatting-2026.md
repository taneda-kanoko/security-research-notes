# Anthropic Claude Code npm package squatting attack (2026-04-01)

> 個人研究メモ。Solo Purple Team手法による攻撃・防御両視点の分析。

---

##### Incident（インシデント概要）


**発生日**: 2026-04-01（axios攻撃の翌日）

**背景**: Claude Codeソースコード漏洩（2026-03-31、v2.1.88）

**漏洩発見者**: Chaofan Shou（@shoucccc）

**漏洩原因**: Bunのバグ（[oven-sh/bun#28001](https://github.com/oven-sh/bun/issues/28001)）により本番モードでもソースマップが配信

**漏洩規模**: 59.8MBのソースマップファイルに512,000行のTypeScriptコード

**攻撃タイプ**: Typosquatting / Dependency Confusion Attack

**攻撃者**: pacifier136（使い捨てメールslmails.com使用）

**スクワッティングされたパッケージ**:

* 最初に確認（2026-04-01）: color-diff-napi, modifiers-napi
* その後確認: audio-capture-napi, image-processor-napi, url-handler-napi

**現在の状態**: 空のスタブとして公開中（後で悪意あるアップデートをプッシュする準備段階）

**警告した研究者**: Clément Dumas（Xにて警告スレッドを公開）

##### Attack Chain（攻撃の流れ）

1. **Reconnaissance（偵察）**: Claude Codeソースコード漏洩を発見
   * 2026-03-31、v2.1.88のソースマップファイルがnpmレジストリに公開
   * 512,000行のTypeScriptコードが数時間以内にGitHubにミラーリング
   * 数千人の開発者がソースコードを分析開始
2. **Target Identification（標的特定）**: 内部パッケージ名の抽出
   * ソースコードから"-napi"サフィックスを持つ内部パッケージ名を特定
   * これらは公開npmレジストリには存在しない（内部専用）
3. **Package Squatting（パッケージスクワッティング）**: 先取り登録
   * 攻撃者pacifier136が使い捨てメールでnpmアカウント作成
   * 漏洩発見から約24時間以内にまず2パッケージを登録、その後5パッケージに拡大
   * 空のスタブとして公開（現時点では無害）
4. **Waiting for Victims（被害者を待つ）**:
   * 漏洩コードをコンパイルしようとする開発者がnpm installを実行
   * dependency resolutionで公開レジストリの攻撃者パッケージが選択される
   * 現時点では無害だが、攻撃者はいつでも悪意あるコードをプッシュ可能
5. **Future Exploitation（将来の悪用）**: 後で悪意あるアップデートをプッシュ
   * postinstallスクリプト追加
   * RATダウンロード
   * C2通信確立

##### ATT&CK Mapping（MITRE ATT&CKフレームワークとの対応）

* **T1195.001** (Supply Chain Compromise: Compromise Software Dependencies)
  + サプライチェーン攻撃：ソフトウェア依存関係の侵害
* **T1036.005** (Masquerading: Match Legitimate Name or Location)
  + 偽装：正規の名前または場所に一致
* **T1608.001** (Stage Capabilities: Upload Malware)
  + 能力の段階的準備：マルウェアのアップロード（将来の悪用）

##### Attack Context（攻撃の文脈）

**axios攻撃との関連性**:

* axios攻撃: 2026-03-31 00:21-03:29 UTC（約3時間）
* Claude Codeソース漏洩発見: 2026-03-31（同日）
* パッケージスクワッティング: 2026-04-01（翌日）
* **時系列的な機会主義的攻撃**: axios攻撃の混乱に乗じた第二波攻撃

**Dependency Confusion攻撃の仕組み**:

```
開発者が漏洩コードをコンパイル
↓
npm install実行
↓
内部パッケージ名（例: color-diff-napi）が必要
↓
npm dependency resolution:
  プロジェクト内のnode_modulesを検索 → 見つからない
  公開npmレジストリを検索 → 攻撃者のパッケージを発見
  攻撃者のパッケージをインストール
↓
攻撃成功（現時点では無害だが、後で悪用可能）
```

##### Detection Hypothesis（検知仮説）

**H1: 短期間に複数の-napiパッケージが同一アカウントから公開**

* 検知指標: 同一npmアカウントから24時間以内に複数パッケージ公開
* 根拠: 通常の開発者は短期間に複数のパッケージを公開しない
* ログソース: npm registry audit log、公開タイムスタンプ
* 追加指標: 使い捨てメール（slmails.com）使用、過去の公開履歴なし

**H2: パッケージ名が既知の内部パッケージ命名規則に一致**

* 検知指標: "-napi"サフィックス + 汎用的な機能名（color-diff, audio-capture等）
* 根拠: これらの名前はAnthropicの内部パッケージ名と一致
* 検知方法: 漏洩ソースコードとnpmレジストリの新規公開パッケージを照合
* ログソース: ソースコード分析、npm registry新規公開通知

**H3: 空のスタブパッケージ（実装がほぼない）**

* 検知指標: パッケージサイズが小さい（数KB）、基本的なmodule.exportsのみ
* 根拠: 正規の-napiパッケージは通常C++バインディングを含みサイズが大きい
* 検知方法: パッケージ内容の自動解析、ファイルサイズ監視
* 疑わしいパターン: 実装コードがない、依存関係がない、テストがない

##### Pre-Lab Simulation（脅威モデリング）

**攻撃者視点（Red Team思考）**:

* Q1: どうやってソースコード漏洩を発見したか?
  + GitHub/Twitter監視、セキュリティニュースフィード、自動化されたソースコード漏洩検知
* Q2: どのタイミングでパッケージをスクワッティングするか?
  + 漏洩発見後24時間以内（他の攻撃者に先を越される前）
  + 開発者がコンパイルを試み始める前（需要が発生する前に供給を確保）

**防御者視点（Blue Team思考）**:

* Defense 1: npm registry監視
  + 新規公開パッケージの命名パターン分析
  + 短期間に複数パッケージを公開するアカウントのフラグ
  + 使い捨てメールドメイン（slmails.com等）の検知
* Defense 2: ソースコード漏洩後の迅速な対応
  + 内部パッケージ名のリストを作成
  + npmレジストリでこれらの名前を先取り登録（defensive registration）
  + または内部パッケージ名を変更（例: @anthropic-internal/color-diff-napi）
* Defense 3: 開発者教育
  + 漏洩コードをコンパイルしない（法的・倫理的理由）
  + package-lock.jsonの依存関係を確認
  + 不明なパッケージをインストールしない

##### Comparison with axios attack（axios攻撃との比較）

| 項目 | axios攻撃 | Anthropicスクワッティング攻撃 |
| --- | --- | --- |
| **攻撃タイプ** | アカウント侵害 → 既存パッケージ改ざん | Typosquatting → 新規パッケージ登録 |
| **標的** | 既存axios利用者（広範囲） | 漏洩コードをコンパイルする開発者（限定的） |
| **即座の危険性** | 高（RATを即座にダウンロード） | 低（現時点では空のスタブ） |
| **持続性** | 低（3時間で削除） | 高（パッケージが削除されるまで存在） |
| **検知難易度** | 中（既存パッケージの変更検知） | 高（新規パッケージは正常に見える） |
| **OPSEC** | 低（即座に悪用、短時間で露見） | 高（段階的攻撃、長期的な待機） |
