# File & Directory Operations

Connect to a shared folder using `client.connectShare(shareName)`. The returned `SmbShare` instance holds the SMB2 `TREE_CONNECT` session and provides file and directory operations using relative paths. Both forward slashes (`/`) and backslashes (`\`) are accepted as path separators and normalized internally.

## Directory Traversal and Metadata

To list entries directly under the share root, call `share.listDirectory("")`. Internally, this repeatedly executes `SMB2 QUERY_DIRECTORY` with `FileIdBothDirectoryInformation` (Class 37) until the server returns `STATUS_NO_MORE_FILES`, returning all entries except the current directory (`.`) and parent directory (`..`).

```kotlin
val entries = share.listDirectory("Videos/Movies", pattern = "*")
for (entry in entries) {
    if (entry.isDirectory) {
        println("[DIR]  ${entry.name}")
    } else {
        println("[FILE] ${entry.name} (${entry.size} bytes, modified=${entry.lastWriteTimeMillis})")
    }
}
```

Use `share.exists(path)` to check whether a path exists, and `share.stat(path)` to inspect its size, timestamps, and attribute flags. `exists` catches `STATUS_OBJECT_NAME_NOT_FOUND`, `STATUS_OBJECT_PATH_NOT_FOUND`, and `STATUS_NO_SUCH_FILE` and returns `false`, while propagating other errors such as insufficient permissions (`STATUS_ACCESS_DENIED`) as an `SmbException`.

## One-Shot Read, Write, Create, Delete, and Rename

For reading or writing small configuration or text files in a single call, use the convenience methods on `SmbShare`:

```kotlin
// Write text (uses FILE_OVERWRITE_IF when overwrite = true)
share.writeText("config/settings.json", """{"theme":"dark"}""", overwrite = true)

// Read text or raw bytes
val json = share.readText("config/settings.json")
val rawBytes = share.readBytes("config/settings.json")

// Append bytes to the end of a file (creates the file if it does not exist)
share.appendBytes("logs/app.log", "Started\n".encodeToByteArray())

// Create, rename, and delete directories and files
share.createDirectory("archive")
share.rename("config/settings.json", "archive/settings.bak", replaceIfExists = true)
share.deleteFile("archive/settings.bak")
share.deleteDirectory("archive")
```

## Low-Level File Handles (`SmbFile`) and Byte-Range Locks

Use `share.openFile` when you need fine-grained control over Windows / SMB access masks (`SmbAccessMask`), share access modes (`SmbShareAccess`), and creation dispositions (`SmbCreateDisposition`).

Pass `shareAccess = SmbShareAccess.EXCLUSIVE` to prevent other processes from opening the file concurrently. To acquire an exclusive or shared lock on a specific byte range while keeping the file open, use `SmbFile.lock` and `SmbFile.unlock` (`SMB2 LOCK`).

```kotlin
import com.sorrowblue.kmcifs.client.protocol.SmbAccessMask
import com.sorrowblue.kmcifs.client.protocol.SmbCreateDisposition
import com.sorrowblue.kmcifs.client.protocol.SmbShareAccess

val file = share.openFile(
    path = "database/records.dat",
    desiredAccess = SmbAccessMask.WRITE_DEFAULT,
    shareAccess = SmbShareAccess.FILE_SHARE_READ or SmbShareAccess.FILE_SHARE_WRITE,
    createDisposition = SmbCreateDisposition.FILE_OPEN_IF,
)

try {
    // Acquire an exclusive lock on the first 4096 bytes (fail immediately on conflict)
    file.lock(offset = 0L, length = 4096L, exclusive = true, failImmediately = true)
    try {
        val header = file.read(offset = 0L, length = 64)
        file.write(offset = 64L, data = byteArrayOf(1, 2, 3, 4))
        file.flush()
    } finally {
        file.unlock(offset = 0L, length = 4096L)
    }
} finally {
    file.closeSuspend()
}
```
