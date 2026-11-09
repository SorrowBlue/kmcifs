# Sample Applications

The `sample` modules in this repository serve as a working reference implementation for file browsing and on-demand video streaming powered by `kmcifs-client`.

## Common Module (`sample`) Architecture

All logic outside the platform UI layer lives in the shared `sample` module.

Connection settings are persisted using `SmbCredentialCipher`. It serializes the hostname, port, credentials, encryption policy, and the last opened share and directory path, then encrypts the payload with `AES-128-GCM` using a random 12-byte IV and a 16-byte authentication tag before saving it on the device.

To play multi-gigabyte video files without waiting for a full download, the sample combines `SmbRandomAccessStream` and `SmbHttpRangeServer`. `SmbRandomAccessStream` divides a file into fixed 256KB blocks and maintains an in-memory LRU cache of up to 32MB (128 blocks). Because the cache lock is separated from the network I/O lock, reads hitting cached blocks return immediately without waiting for background prefetch requests. Asynchronous prefetching of 1MB (4 blocks) is triggered only when consecutive blocks are requested (sequential playback), avoiding wasted read-ahead during isolated random seeks such as container index probing at the end of a file.

`SmbHttpRangeServer` uses `ktor-network` to spin up a lightweight HTTP 1.1 server on an available port on `127.0.0.1`, streaming data from `SmbRandomAccessStream` with `206 Partial Content` responses to `Range: bytes=start-end` requests. Serving over HTTP Range rather than a local file descriptor (`fd://`) tells media players like VLC that the source is seekable but not a fast local disk (`STREAM_CAN_FASTSEEK = false`), allowing playback of 9GB+ OpenDML AVI 2.0 files to start in seconds without scanning the entire file index upfront.

## Platform Applications

### Android (`sample/androidApp`)

A three-screen Jetpack Compose (Material 3) application consisting of a connection settings screen, a share and directory browser screen, and a file viewer screen. Connection credentials are encrypted using a hardware-backed `AES/GCM/NoPadding` secret key in the Android Keystore. Video playback embeds `org.videolan.android:libvlc-all` (LibVLC) to play H.264 / HEVC / MPEG-4 video and Dolby AC3 / EAC3 / AAC audio via the local HTTP streaming server.

```bash
./kotlin build -m androidApp
```

### Windows Native GUI (`sample/windowsApp`)

A native GUI application that calls the Win32 API (`CreateWindowExW`) directly from Kotlin/Native (`mingwX64`). It stores encrypted connection settings in `%APPDATA%\kmcifs\connection.enc` and provides a two-pane list box for shares and files, a text preview pane, and integration with VLC or the default media player via the local HTTP Range streaming server. Passing command-line arguments launches the app in CLI mode.

```powershell
.\kotlin.bat run -m windowsApp
```

### iOS (`sample/iosApp`)

Drives UIKit (`UINavigationController` / `UITableViewController`) and `AVPlayerViewController` from Kotlin/Native, combining the iOS Keychain (`SecItemAdd` / `SecItemCopyMatching`) with `SmbCredentialCipher` to protect saved connection credentials.

### JVM / Linux / macOS CLI (`sample/jvmApp`, `sample/linuxApp`, `sample/macosApp`)

Accepts command-line arguments or environment variables (`SMB_HOST`, `SMB_USER`, `SMB_PASSWORD`, `SMB_SHARE`, etc.) to list shared folders, browse directories, preview text headers, and verify random-access streaming on video files.

```bash
./kotlin run -m jvmApp -- --host=192.168.1.100 --user=alice --password=secret --share=Public
```
