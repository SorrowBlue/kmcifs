# kmcifs

Kotlin Multiplatform 向けの SMB2 / SMB3 クライアントライブラリです。ビルドシステムには Gradle ではなく **Kotlin Toolchain** (`project.yaml` / `module.yaml`) を使用し、プラットフォーム固有のネイティブコード（Swift / Objective-C / C / Java 固有 API）を介さず共通の Kotlin コード（`src/`）と `ktor-network` のみで動作します。

## 特徴と対応範囲

プロトコルは SMB 2.0.2、2.1、3.0、3.0.2、3.1.1 に対応しています。認証には SPNEGO ラップされた NTLMSSP (NTLMv2) とゲスト・匿名ログインを使用し、セッション鍵の交換 (`NTLMSSP_NEGOTIATE_KEY_EXCH`) や MIC 検証を含みます。

セキュリティ面では、SMB 2.x の `HMAC-SHA256` 署名と SMB 3.x の `AES-128-CMAC` 署名に加え、Transform Header (`0xFD 'S' 'M' 'B'`) を用いた `AES-128-GCM` / `AES-128-CCM` によるパケット全体の暗号化通信をサポートしています。暗号プリミティブと NIST SP800-108 鍵導出はすべて共通 Kotlin コード内で実装されているため、ターゲット環境ごとの暗号 API 差異に影響されません。

ファイル操作はディレクトリの走査、ファイルの読み書き、作成、削除、リネーム、サイズ変更、およびバイト範囲の排他ロック・共有ロック (`SMB2 LOCK`) を備えています。さらに `IPC$` 共有上の名前付きパイプ操作と、`srvsvc` パイプ上の DCE/RPC (`NetrShareEnum`) を利用したサーバー共有フォルダ一覧の取得にも対応しています。

## ビルドとローカル公開 (Kotlin Toolchain)

テストの実行およびローカル Maven リポジトリ（`mavenLocal`）への公開は、同梱の `kotlin` / `kotlin.bat` ラッパーから実行します。

```bash
# テストの実行
./kotlin test

# mavenLocal への公開
./kotlin publish mavenLocal
```

### Kotlin Toolchain プロジェクトからの利用 (`module.yaml`)

```yaml
repositories:
  - url: mavenLocal

dependencies:
  - com.sorrowblue.kmcifs:kmcifs-client:0.0.1
```

### Gradle KMP プロジェクトからの利用 (`build.gradle.kts`)

```kotlin
kotlin {
    sourceSets {
        commonMain.dependencies {
            implementation("com.sorrowblue.kmcifs:kmcifs-client:0.0.1")
        }
    }
}
```

## 基本的な使い方

### 接続と共有フォルダ一覧の取得

```kotlin
import com.sorrowblue.kmcifs.client.SmbClient
import com.sorrowblue.kmcifs.client.SmbConfig
import com.sorrowblue.kmcifs.client.SmbEncryptionPolicy
import com.sorrowblue.kmcifs.client.auth.SmbCredentials

val credentials = SmbCredentials(
    username = "user",
    password = "password",
    domain = "WORKGROUP"
)

val config = SmbConfig(
    encryptionPolicy = SmbEncryptionPolicy.NEGOTIATE,
    preferEncryption = true
)

val client = SmbClient.connect(
    host = "192.168.1.100",
    credentials = credentials,
    config = config
)

try {
    val shares = client.listShares()
    for (share in shares) {
        println("${share.name} (${share.type}) - ${share.comment}")
    }
} finally {
    client.closeSuspend()
}
```

### ファイルの一覧取得・読み書き・排他ロック

```kotlin
val share = client.connectShare("Documents")
try {
    // ディレクトリ一覧の取得
    val entries = share.listDirectory("reports")
    for (entry in entries) {
        println("${entry.name}: ${entry.size} bytes (dir=${entry.isDirectory})")
    }

    // テキストの書き込みと読み取り
    share.writeText("reports/summary.txt", "Quarterly result")
    val text = share.readText("reports/summary.txt")

    // 排他ロックを伴うランダムアクセス操作
    val file = share.openFile("reports/summary.txt")
    try {
        file.lock(offset = 0L, length = 1024L, exclusive = true)
        val chunk = file.read(offset = 0L, length = 64)
        file.unlock(offset = 0L, length = 1024L)
    } finally {
        file.closeSuspend()
    }

    // リネームと削除
    share.rename("reports/summary.txt", "reports/summary_archived.txt")
    share.deleteFile("reports/summary_archived.txt")
} finally {
    share.closeSuspend()
}
```
