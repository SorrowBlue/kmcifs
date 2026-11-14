# AGENTS.md

`kmcifs` リポジトリで開発・調査を行うエージェント向けの技術ガイドライン。詳細な行動規範やワークフローは `.agents/rules/` および `.agents/skills/` 配下の定義に従うこと。

## ビルドシステムと検証コマンド

このプロジェクトは Gradle ではなく Kotlin Toolchain（Amper ベースの `project.yaml` / `module.yaml`）で管理されている。コマンドはリポジトリルートの `./kotlin`（macOS / Linux）または `.\kotlin.bat`（Windows）から実行する。

日常のコード変更時は、全ターゲットのビルドではなく JVM ターゲットを指定したテスト実行が最も高速で確実なフィードバック手段となる。

```powershell
# コアクライアントの JVM テスト実行（暗号プリミティブ + SMB 3.1.1 E2E テスト）
.\kotlin.bat test -m kmcifs-client -p jvm

# サンプル共通モジュールの JVM テスト実行
.\kotlin.bat test -m sample -p jvm

# Detekt 静的解析（標準ルール + ktlint + Compose Rules）
.\kotlin.bat check detekt

# Detekt ベースラインの再生成
.\kotlin.bat do detektBaseline

# Dokka API リファレンス生成
.\kotlin.bat do dokka
```

実機やエミュレータに対する自動操作（`adb shell input`、画面キャプチャ、`mobile-mcp` による UI 操作など）は、ユーザーからの明示的な指示がない限り禁止されている（`.agents/rules/device-operation-rules.md`）。

## 設計方針とアーキテクチャ上の不変条件

`kmcifs-client` は C ライブラリやプラットフォーム固有 API に依存せず、`ktor-network` と `kotlinx-io-core` のみを用いて Pure Kotlin（`commonMain` 相当の単一 `src/` ツリー）で SMB 2.0.2〜3.1.1 を実装している。

開発における最優先の設計方針は、**SMB 2.x / 3.x の公式プロトコル仕様（[MS-SMB2]、[MS-NLMP]、[MS-SRVS] 等）への厳格な準拠**である。パケット構造、フィールドのアライメントや予約領域、フラグやステータスの解釈、クレジット計算、署名・暗号化の適用条件、および状態遷移に変更や最適化を加える際は、独自の推測や場当たり的なワークアラウンドを避け、必ず該当する仕様書の規定を根拠とすること。Windows Server / クライアント、Samba、各種 NAS など異なるサーバー実装間の相互運用性を損なわないため、以下の不変条件を崩してはならない。

### 1. 非同期パイプライン送受信と `MessageId` 採番 (`SmbClient`)
1つの `SmbClient` インスタンスは単一の TCP ソケットを共有し、SMB2 クレジット制御のもとで非同期パイプライン送信と `MessageId` による応答多重分離（Demultiplexing）を行う。複数のコルーチンや複数の `SmbRandomAccessFile` / `SmbFile` から並列に呼び出された際、送信側は先行リクエストの応答到着を待たずにパイプライン送信し、オンデマンドで起動する受信ループが到着順に各待機中リクエスト（`PendingExchange`）へ応答を振り分ける。

SMB2 ヘッダの `MessageId` は、`CreditCharge`（オフセット `6`）に基づいて必ず `sendMutex.withLock` の内部で採番してそのままソケットへ書き出し、ワイヤ上の送信順と `MessageId` の単調増加（および Compound パケット内の連番）を一致させる。`sendMutex` の外で先行採番してはならない。

### 2. SMB3 署名・暗号化ポリシーと Compound Request (`protocol`, `crypto`)
SMB 3.x ネゴシエーション時、`alwaysSign = false` かつサーバー側が署名を必須（`SMB2_NEGOTIATE_SIGNING_REQUIRED`）としていない場合は、MS-SMB2 3.2.5.3.1 に従い `TREE_CONNECT` のみを署名対象とする。これにより `READ` や `QUERY_DIRECTORY` における不要な `AES-128-CMAC` 計算を省いている。一方、サーバーからの応答に対しては既定で `verifyServerSignatures = true` とし、最終 `SESSION_SETUP` 応答や署名必須対象コマンドで署名検証および署名ストリッピングの拒否（MS-SMB2 3.2.5.1.3）を行う。

`SmbShare` の `stat`・`createDirectory`（`[CREATE + CLOSE]`）、`listDirectory`（`[CREATE + 初回 QUERY_DIRECTORY]`）、および `deleteFile`・`deleteDirectory`・`rename`（`[CREATE + SET_INFO + CLOSE]`）では RTT 削減のため Compound Related Request（MS-SMB2 3.2.4.1.4）を使用する。2番目以降の関連リクエストには `SMB2_FLAGS_RELATED_OPERATIONS` に加え、`FileId = 0xFFFFFFFFFFFFFFFF / 0xFFFFFFFFFFFFFFFF`、`TreeId = 0xFFFFFFFF`、`SessionId = 0xFFFFFFFFFFFFFFFF` を設定する。先行コマンドがエラーとなりサーバーが後続レスポンスを省略した場合でも、受信ループがタイムアウトまで待機しないよう制御している。

`Aes.kt` では 16 バイト鍵（`ULong` 2語）をキーとする `KeyContext` キャッシュにより、ラウンド鍵・GHASH 用 4-bit Shoup テーブル・CMAC サブ鍵の再計算を回避している。`KeyContext` は複数スレッドから参照されるため、完全に不変（Immutable）な構造を維持すること。

### 3. ゼロコピー読み取りとランダムアクセス (`SmbFile`, `SmbRandomAccessFile`)
大容量読み取りやアーカイブ解析で中間 `ByteArray` の生成を防ぐため、`SmbFile.readInto` と `SmbMessages.parseReadResponseInto` が呼び出し元バッファへ直接ペイロードを書き込む。

`SmbRandomAccessFile` の読み書きメソッド（`read`、`write`、`setLength`、`flush`、`close`）は、既存のストリーム抽象や `java.io.RandomAccessFile` 互換の呼び出し元から扱いやすいよう非 `suspend` 関数として提供している。既定のバッファサイズ（`DEFAULT_BUFFER_SIZE`）は `jcifs-ng` と同じく `0`（バッファリングなし）であり、細切れのシーク読み取りで余分な通信を発生させない。1つの `SmbRandomAccessFile` インスタンスは単一スレッドから順次操作する前提とし、プリミティブ読み書きにはインスタンス内の `scratchBuffer`（8バイト）を再利用してヒープ割り当てを抑えている。

`kotlinx.io` 連携（`asRawSource` / `asSource`、`asRawSink` / `asSink`）では、`kotlinx.io` の 8KB セグメント単位の呼び出しがそのまま 8KB の SMB パケットに細分化されないよう、64KB 単位のプリフェッチおよびバッチ書き込みを行っている。

## 言語・ドキュメント・Git 規約

- **対話と成果物:** ユーザーへのチャット応答や計画・解説ドキュメントは日本語で記述する。日本語の技術文書やコメントを作成する際は、定型的な前置きや過剰な箇条書き・記号を避け、文脈のつながりで自然に読ませる（`.agents/rules/language-strategies.md`）。
- **コード:** 識別子やコード内の記述には標準的な英語を用いる。
- **コミットと Pull Request:** コミットメッセージは staged 変更のみを対象とし、英語の Conventional Commits 形式（`<type>[optional scope]: <description>`、件名1行のみ・50文字以内・末尾ピリオドなし）を厳守する。論理的に独立した変更は1コミットずつ分割し、Pull Request のタイトルと本文も英語で記述する（`.agents/rules/git-commit-rules.md`）。
