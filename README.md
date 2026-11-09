# kmcifs

[![Maven Central Version](https://img.shields.io/maven-central/v/com.sorrowblue.kmcifs/kmcifs-client)](https://central.sonatype.com/artifact/com.sorrowblue.kmcifs/kmcifs-client)
[![GitHub Release](https://img.shields.io/github/v/release/SorrowBlue/kmcifs)](https://github.com/SorrowBlue/kmcifs/releases)
[![CI](https://github.com/SorrowBlue/kmcifs/actions/workflows/ci.yml/badge.svg)](https://github.com/SorrowBlue/kmcifs/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

English | [日本語](README.ja.md)

An SMB2 / SMB3 client implementation for Kotlin Multiplatform. Built with the Kotlin Toolchain (`project.yaml` / `module.yaml`) instead of Gradle, it implements all protocol handling and cryptographic operations in common Kotlin code (`src/`) with only `ktor-network` and `kotlinx-io` as external dependencies. It provides identical behavior across JVM, Android, iOS (`iosArm64` / `iosSimulatorArm64`), macOS (`macosArm64`), Linux (`linuxX64` / `linuxArm64`), and Windows (`mingwX64`) without relying on platform-specific C libraries or OS APIs.

## Protocol Support and Design

Supported dialects are SMB 2.0.2, 2.1, 3.0, 3.0.2, and 3.1.1. During SMB 3.1.1 negotiation, the client exchanges Preauth Integrity Capabilities (`SHA-512`) and Encryption Capabilities (`AES-128-GCM` / `AES-128-CCM`). Authentication supports SPNEGO-wrapped NTLMSSP (NTLMv2, `NTLMSSP_NEGOTIATE_KEY_EXCH`, and MIC verification) as well as guest and anonymous sessions.

All cryptographic primitives required for signing and encryption (`MD4`, `MD5`, `HMAC-SHA256`, `SHA-512`, `RC4`, `AES-128-CMAC`, `AES-128-CCM`, and `AES-128-GCM`) along with the NIST SP800-108 counter-mode KDF are implemented directly in `kmcifs-client`. Packet signing uses `HMAC-SHA256` for SMB 2.x and `AES-128-CMAC` for SMB 3.x. When encryption is required or when connecting to an encrypted share, entire packets are protected using the SMB 3.x Transform Header (`0xFD 'S' 'M' 'B'`). For throughput-critical workloads such as large video streaming, combining `SmbEncryptionPolicy.NEGOTIATE` with `preferEncryption = false` satisfies mandatory SMB 3.x request signing while avoiding the CPU overhead of software AES-GCM decryption on unencrypted shares.

Filesystem operations cover directory enumeration, random-offset reads and writes, file creation, deletion, renaming, truncation, and byte-range exclusive or shared locking (`SMB2 LOCK`). Named pipe communication over the `IPC$` share and DCE/RPC over the `srvsvc` pipe (`NetrShareEnum`) are also built in, allowing direct enumeration of shared folders on the target server.

## Module Structure

The repository consists of the core `kmcifs-client` library and the `sample` module suite, which provides a shared file browser and media streaming foundation.

The common `sample` module includes AES-128-GCM encrypted credential storage (`SmbCredentialCipher`), a random-access stream with a 256KB block LRU cache and sequential prefetching (`SmbRandomAccessStream`), and a local loopback HTTP 1.1 Range streaming server returning `206 Partial Content` (`SmbHttpRangeServer`). Built on top of this shared layer are the Android app (`sample/androidApp`, Compose UI + LibVLC), the iOS app (`sample/iosApp`, UIKit + AVPlayer), the Windows native GUI app (`sample/windowsApp`, Win32 API + external player integration), and CLI samples (`sample/jvmApp`, `sample/linuxApp`, `sample/macosApp`).

## Building and Running

Use the bundled `kotlin` (Unix) or `kotlin.bat` (Windows) wrapper to build, run tests, and publish to the local Maven repository (`mavenLocal`).

```bash
# Run tests across all modules
./kotlin test

# Generate Dokka HTML API reference (build/dokka/html/kmcifs-client/index.html)
./kotlin do dokka

# Build Zensical documentation site (English: build/site, Japanese: build/site/ja) and preview locally
uvx --python 3.13 zensical build
uvx --python 3.13 zensical build -f zensical.ja.toml
uvx --python 3.13 zensical serve

# Publish to mavenLocal
./kotlin publish mavenLocal

# Launch the Windows native GUI sample (Windows)
.\kotlin.bat run -m windowsApp

# Build the Android sample
./kotlin build -m androidApp
```

### Using from a Kotlin Toolchain project (`module.yaml`)

```yaml
repositories:
  - url: mavenLocal

dependencies:
  - com.sorrowblue.kmcifs:kmcifs-client:<version>
```

### Using from a Gradle KMP project (`build.gradle.kts`)

```kotlin
kotlin {
    sourceSets {
        commonMain.dependencies {
            implementation("com.sorrowblue.kmcifs:kmcifs-client:<version>")
        }
    }
}
```

## Basic Usage

### Establishing a Session and Listing Shares

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

### File Operations and Random Access

```kotlin
val share = client.connectShare("Documents")
try {
    for (entry in share.listDirectory("reports")) {
        println("${entry.name}: ${entry.size} bytes (dir=${entry.isDirectory})")
    }

    share.writeText("reports/summary.txt", "Quarterly result")
    val text = share.readText("reports/summary.txt")

    // Random-access operations modeled after java.io.RandomAccessFile
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
