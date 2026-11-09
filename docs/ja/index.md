# kmcifs

`kmcifs` は Kotlin Multiplatform 向けの SMB2 / SMB3 クライアントライブラリである。プラットフォーム固有のネイティブライブラリや OS 依存の暗号 API を一切使わず、`ktor-network` と `kotlinx-io` のみを土台として共通 Kotlin コードだけでプロトコル処理と暗号演算を実装している。

対応ターゲットは JVM、Android（`minSdk 26`）、iOS（`iosArm64` / `iosSimulatorArm64`）、macOS（`macosArm64`）、Linux（`linuxX64` / `linuxArm64`）、Windows（`mingwX64`）の 8 環境。いずれのターゲットでも同一の API と通信挙動を提供する。クラス・メソッド単位の網羅的な仕様は [Dokka API リファレンス](../api/index.html) を参照。

## 対応プロトコルと暗号仕様

ダイアレクトは SMB 2.0.2、2.1、3.0、3.0.2、3.1.1 を網羅している。サーバーとのネゴシエーション時にはクライアント側で対応可能なダイアレクト一覧を提示し、SMB 3.1.1 が選択された場合は `SHA-512` による Preauth Integrity Hash（通信改ざん検知用の連鎖ハッシュ）と `AES-128-GCM` / `AES-128-CCM` の Encryption Capabilities Context を交換する。

認証は SPNEGO ラップされた NTLMSSP（NTLMv2）およびゲスト・匿名セッションに対応する。NTLMv2 認証では `MD4` / `HMAC-MD5` による NT Proof 計算、`RC4` によるセッション鍵交換（`NTLMSSP_NEGOTIATE_KEY_EXCH`）、メッセージ完全性コード（MIC）の生成・検証を行い、確立したセッション鍵から NIST SP800-108 カウンタモード KDF を用いて署名鍵と暗号化・復号鍵を導出する。パケット署名は SMB 2.x が `HMAC-SHA256`、SMB 3.x が `AES-128-CMAC`。パケット暗号化は SMB 3.x Transform Header（`0xFD 'S' 'M' 'B'`）を用いた `AES-128-GCM` および `AES-128-CCM` で動作する。

## 導入方法

リポジトリのルートに同梱されている `kotlin`（または `kotlin.bat`）でローカル Maven リポジトリへ公開できる。

```bash
./kotlin publish mavenLocal
```

Kotlin Toolchain（Amper）プロジェクトから参照する場合は `module.yaml` に `mavenLocal` と依存関係を追加する。

```yaml
repositories:
  - url: mavenLocal

dependencies:
  - com.sorrowblue.kmcifs:kmcifs-client:0.0.1
```

Gradle ベースの Kotlin Multiplatform プロジェクトから利用する場合は `build.gradle.kts` の `commonMain` に追加する。

```kotlin
repositories {
    mavenLocal()
    mavenCentral()
}

kotlin {
    sourceSets {
        commonMain.dependencies {
            implementation("com.sorrowblue.kmcifs:kmcifs-client:0.0.1")
        }
    }
}
```

## 最小構成のコード例

サーバーへ接続して共有フォルダ一覧を取得し、特定の共有フォルダ内のファイルを読み取る一連の流れを示す。リソース解放には `AutoCloseable` の `close()` ではなく、サーバーへ明示的に `SMB2 CLOSE` / `TREE_DISCONNECT` / `LOGOFF` パケットを送信する `closeSuspend()` を使用する。

```kotlin
import com.sorrowblue.kmcifs.client.SmbClient
import com.sorrowblue.kmcifs.client.SmbConfig
import com.sorrowblue.kmcifs.client.SmbEncryptionPolicy
import com.sorrowblue.kmcifs.client.auth.SmbCredentials

suspend fun fetchReport() {
    val credentials = SmbCredentials(
        username = "alice",
        password = "secret",
        domain = "WORKGROUP",
    )
    val config = SmbConfig(
        encryptionPolicy = SmbEncryptionPolicy.NEGOTIATE,
        preferEncryption = false,
    )

    val client = SmbClient.connect(
        host = "192.168.1.100",
        credentials = credentials,
        config = config,
    )

    try {
        for (shareInfo in client.listShares()) {
            println("Share: ${shareInfo.name} (${shareInfo.comment})")
        }

        val share = client.connectShare("Public")
        try {
            val content = share.readText("docs/readme.txt")
            println(content)
        } finally {
            share.closeSuspend()
        }
    } finally {
        client.closeSuspend()
    }
}
```
