# Connection, Authentication & Encryption

Connecting to an SMB server starts with `SmbClient.connect`. Establishing the TCP connection (default port `445` with `TCP_NODELAY` enabled), negotiating the protocol dialect via `SMB2 NEGOTIATE`, and completing the two-round-trip NTLMv2 authentication via `SMB2 SESSION_SETUP` all take place within this call.

## Specifying Credentials

Store the username, password, and domain (or workgroup name) in `SmbCredentials`. For NAS devices or standalone Windows shares outside an Active Directory domain, leave `domain` as an empty string or `"WORKGROUP"`. To connect to an unauthenticated guest share, pass `SmbCredentials.Guest` or `SmbCredentials.Anonymous`.

```kotlin
import com.sorrowblue.kmcifs.client.SmbClient
import com.sorrowblue.kmcifs.client.auth.SmbCredentials

// NTLMv2 authentication
val credentials = SmbCredentials(
    username = "mediauser",
    password = "MyPassword123",
    domain = "WORKGROUP",
)

// Guest connection
val guestCredentials = SmbCredentials.Guest
```

## Signing and Encryption Trade-offs (`SmbConfig`)

SMB 3.x provides two levels of traffic protection: per-packet signing (`AES-128-CMAC`) and full-payload encryption (`AES-128-GCM` / `AES-128-CCM`) using the Transform Header. Because `kmcifs-client` implements AES in pure Kotlin to guarantee cross-platform consistency, these settings directly affect transfer throughput.

Under the MS-SMB2 specification (Section 3.3.5.7), SMB 3.1.1 requests such as `TREE_CONNECT` must be signed whenever they are not encrypted; Windows Server and Samba reject unsigned unencrypted requests with `STATUS_ACCESS_DENIED`. Outgoing `READ` requests from the client are only 113 bytes, so the computational cost of attaching an `AES-128-CMAC` signature is negligible. By contrast, decrypting and verifying every 256KB `READ` response from the server with software `AES-128-GCM` makes the CPU a bottleneck during high-bandwidth transfers such as video streaming.

With this characteristic in mind, `SmbConfig` lets you choose the appropriate policy for your workload:

```kotlin
import com.sorrowblue.kmcifs.client.SmbConfig
import com.sorrowblue.kmcifs.client.SmbEncryptionPolicy

// High-throughput configuration (for LAN video streaming and large file transfers)
val streamingConfig = SmbConfig(
    encryptionPolicy = SmbEncryptionPolicy.NEGOTIATE,
    preferEncryption = false,
    alwaysSign = true,
    verifyServerSignatures = false,
)

// Full encryption configuration (for sensitive documents or untrusted networks)
val strictEncryptedConfig = SmbConfig(
    encryptionPolicy = SmbEncryptionPolicy.REQUIRED,
    preferEncryption = true,
)
```

When configured with `SmbEncryptionPolicy.NEGOTIATE` and `preferEncryption = false`, the client still negotiates the SMB 3.1.1 Encryption Context and enables encryption whenever required by the server or share (`SMB2_SHAREFLAG_ENCRYPT_DATA`), while communicating at high speed using request signing only on standard shares. If you want to allow connections only when encryption is enforced, specify `SmbEncryptionPolicy.REQUIRED`; if the server does not support SMB 3.x encryption, an `SmbException` is thrown during session setup.

## Listing Shared Folders (`listShares`)

Call `client.listShares()` to retrieve the list of shared folders published on the server. Internally, the client connects to the administrative share `IPC$` via `TREE_CONNECT`, opens the `srvsvc` named pipe, and executes a DCE/RPC `Bind` followed by `NetrShareEnum` (Level 1).

```kotlin
val shares = client.listShares(includeHidden = false)
for (share in shares) {
    println("Name: ${share.name}, Type: ${share.type}, Comment: ${share.comment}")
}
```

With `includeHidden = false` (the default), administrative and hidden shares ending with `$` (such as `IPC$`, `ADMIN$`, and `C$`) as well as shares with the hidden bit set in their type flags are filtered out, returning standard disk shares (`SmbShareType.DISKTREE`). Pass `includeHidden = true` to include hidden shares.
