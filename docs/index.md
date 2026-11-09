# kmcifs

`kmcifs` is an SMB2 / SMB3 client library for Kotlin Multiplatform. It implements all protocol handling and cryptographic operations in common Kotlin code on top of `ktor-network` and `kotlinx-io`, without using any platform-specific native libraries or OS-dependent crypto APIs.

Supported targets cover 8 environments: JVM, Android (`minSdk 26`), iOS (`iosArm64` / `iosSimulatorArm64`), macOS (`macosArm64`), Linux (`linuxX64` / `linuxArm64`), and Windows (`mingwX64`). Every target provides the exact same API and network behavior. For class- and method-level specifications, see the [Dokka API Reference](api/index.html).

## Supported Protocols and Cryptography

Supported dialects span SMB 2.0.2, 2.1, 3.0, 3.0.2, and 3.1.1. During negotiation with the server, the client presents its list of supported dialects; when SMB 3.1.1 is selected, it exchanges the `SHA-512` Preauth Integrity Hash (a chained hash for tamper detection) and the `AES-128-GCM` / `AES-128-CCM` Encryption Capabilities Context.

Authentication supports SPNEGO-wrapped NTLMSSP (NTLMv2) as well as guest and anonymous sessions. NTLMv2 authentication computes the NT Proof via `MD4` / `HMAC-MD5`, performs `RC4` session key exchange (`NTLMSSP_NEGOTIATE_KEY_EXCH`), and generates and verifies the Message Integrity Code (MIC). From the established session key, signing and encryption/decryption keys are derived using the NIST SP800-108 counter-mode KDF. Packet signing uses `HMAC-SHA256` for SMB 2.x and `AES-128-CMAC` for SMB 3.x. Packet encryption operates with `AES-128-GCM` and `AES-128-CCM` using the SMB 3.x Transform Header (`0xFD 'S' 'M' 'B'`).

## Installation

You can publish the library to your local Maven repository using the `kotlin` (or `kotlin.bat`) wrapper included at the root of the repository.

```bash
./kotlin publish mavenLocal
```

When referencing from a Kotlin Toolchain (Amper) project, add `mavenLocal` and the dependency to `module.yaml`:

```yaml
repositories:
  - url: mavenLocal

dependencies:
  - com.sorrowblue.kmcifs:kmcifs-client:0.0.1
```

When using from a Gradle-based Kotlin Multiplatform project, add it to `commonMain` in `build.gradle.kts`:

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

## Minimal Example

The following example connects to a server, lists available shared folders, and reads a file inside a specific share. To release resources cleanly, use `closeSuspend()` rather than `AutoCloseable.close()` so that `SMB2 CLOSE`, `TREE_DISCONNECT`, and `LOGOFF` packets are explicitly sent to the server.

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
