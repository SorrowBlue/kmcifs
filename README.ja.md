# kmcifs

[![Maven Central Version](https://img.shields.io/maven-central/v/com.sorrowblue.kmcifs/kmcifs-client)](https://central.sonatype.com/artifact/com.sorrowblue.kmcifs/kmcifs-client)
[![GitHub Release](https://img.shields.io/github/v/release/SorrowBlue/kmcifs)](https://github.com/SorrowBlue/kmcifs/releases)
[![CI](https://github.com/SorrowBlue/kmcifs/actions/workflows/ci.yml/badge.svg)](https://github.com/SorrowBlue/kmcifs/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

[English](README.md) | 日本語

Kotlin Multiplatform 向けの SMB2 / SMB3 クライアント実装。ビルドシステムには Gradle ではなく Kotlin Toolchain（`project.yaml` / `module.yaml`）を採用し、`ktor-network` と `kotlinx-io` のみを外部依存として共通 Kotlin コード（`src/`）だけでプロトコル処理と暗号演算を完結させている。JVM、Android、iOS（`iosArm64` / `iosSimulatorArm64`）、macOS（`macosArm64`）、Linux（`linuxX64` / `linuxArm64`）、Windows（`mingwX64`）の各ターゲットでプラットフォーム固有の C ライブラリや OS API に頼らず同一の挙動を提供する。

## プロトコル仕様と設計

対応ダイアレクトは SMB 2.0.2、2.1、3.0、3.0.2、3.1.1。SMB 3.1.1 ネゴシエーションでは Preauth Integrity Capabilities（`SHA-512`）と Encryption Capabilities（`AES-128-GCM` / `AES-128-CCM`）を交換し、認証には SPNEGO ラップされた NTLMSSP（NTLMv2、`NTLMSSP_NEGOTIATE_KEY_EXCH`、MIC 検証）およびゲスト・匿名セッションをサポートする。

署名と暗号化に必要なプリミティブ（`MD4`、`MD5`、`HMAC-SHA256`、`SHA-512`、`RC4`、`AES-128-CMAC`、`AES-128-CCM`、`AES-128-GCM`）と NIST SP800-108 カウンタモード KDF はすべて `kmcifs-client` 内に実装されている。SMB 2.x では `HMAC-SHA256`、SMB 3.x では `AES-128-CMAC` によるパケット署名を行い、暗号化要求時や暗号化共有への接続時には Transform Header（`0xFD 'S' 'M' 'B'`）でパケット全体を保護する。大容量の動画ストリーミングのようにスループットが優先される場面では、`SmbEncryptionPolicy.NEGOTIATE` と `preferEncryption = false` を組み合わせることで、SMB 3.x の必須要件であるリクエスト署名を維持したままソフトウェア AES-GCM 復号の負荷を回避できる。

ファイルシステム操作はディレクトリの走査、任意オフセットからのランダムリード・ライト、ファイル作成・削除・リネーム・サイズ変更、バイト範囲の排他・共有ロック（`SMB2 LOCK`）に対応する。`IPC$` 共有上の名前付きパイプ通信と `srvsvc` パイプ上の DCE/RPC（`NetrShareEnum`）を備えており、接続先サーバーの共有フォルダ一覧を直接列挙できる。

## モジュール構成

リポジトリはコアクライアントの `kmcifs-client` と、共通ブラウザ・ストリーミング基盤を持つ `sample` モジュール群で構成される。

`sample` モジュールには、AES-128-GCM による接続情報の暗号化保存（`SmbCredentialCipher`）、256KB ブロック単位の LRU キャッシュとシーケンシャル先読みを備えたランダムアクセスストリーム（`SmbRandomAccessStream`）、ローカルループバック上で HTTP 1.1 `206 Partial Content` を返す Range ストリーミングサーバー（`SmbHttpRangeServer`）が含まれる。この共通基盤の上に、Android アプリ（`sample/androidApp`、Compose UI + LibVLC）、iOS アプリ（`sample/iosApp`、UIKit + AVPlayer）、Windows ネイティブ GUI アプリ（`sample/windowsApp`、Win32 API + 外部プレイヤー連携）、および CLI サンプル（`sample/jvmApp`、`sample/linuxApp`、`sample/macosApp`）を配置している。

## ビルドと実行

同梱の `kotlin`（Unix 系）または `kotlin.bat`（Windows）ラッパーからビルド、テスト、ローカル Maven リポジトリ（`mavenLocal`）への公開を行う。

```bash
# 全モジュールのテスト実行
./kotlin test

# Dokka HTML API リファレンスの生成 (build/dokka/html/kmcifs-client/index.html)
./kotlin do dokka

# Zensical ドキュメントサイトのビルド (英語: build/site, 日本語: build/site/ja) とローカルプレビュー
uvx --python 3.13 zensical build
uvx --python 3.13 zensical build -f zensical.ja.toml
uvx --python 3.13 zensical serve

# mavenLocal への公開
./kotlin publish mavenLocal

# Windows ネイティブ GUI サンプルの起動 (Windows)
.\kotlin.bat run -m windowsApp

# Android サンプルのビルド
./kotlin build -m androidApp
```

### Kotlin Toolchain プロジェクトからの参照 (`module.yaml`)

```yaml
repositories:
  - url: mavenLocal

dependencies:
  - com.sorrowblue.kmcifs:kmcifs-client:<version>
```

### Gradle KMP プロジェクトからの参照 (`build.gradle.kts`)

```kotlin
kotlin {
    sourceSets {
        commonMain.dependencies {
            implementation("com.sorrowblue.kmcifs:kmcifs-client:<version>")
        }
    }
}
```

## 基本的な使い方

### セッション確立と共有フォルダ一覧の取得

```kotlin
import com.sorrowblue.kmcifs.client.SmbClient
import com.sorrowblue.kmcifs.client.SmbConfig
import com.sorrowblue.kmcifs.client.SmbEncryptionPolicy
import com.sorrowblue.kmcifs.client.auth.SmbCredentials

val credentials = SmbCredentials(
    username = "user",
    password = "password",
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
    for (share in client.listShares()) {
        println("${share.name} (${share.type}) - ${share.comment}")
    }
} finally {
    client.closeSuspend()
}
```

### ファイル操作とランダムアクセス

```kotlin
val share = client.connectShare("Documents")
try {
    for (entry in share.listDirectory("reports")) {
        println("${entry.name}: ${entry.size} bytes (dir=${entry.isDirectory})")
    }

    share.writeText("reports/summary.txt", "Quarterly result")
    val text = share.readText("reports/summary.txt")

    // Java の RandomAccessFile に相当するランダムアクセス操作
    val raf = share.openRandomAccessFile("reports/summary.txt", mode = "rw")
    try {
        println("length = ${raf.length}, position = ${raf.position}")
        val firstByte: Byte = raf.readByte()

        raf.seek(10L)
        val buffer = ByteArray(6)
        val bytesRead = raf.read(buffer)

        raf.seek(raf.length)
        raf.write("\nReviewed".encodeToByteArray())
    } finally {
        raf.closeSuspend()
    }

    share.rename("reports/summary.txt", "reports/summary_archived.txt")
    share.deleteFile("reports/summary_archived.txt")
} finally {
    share.closeSuspend()
}
```
