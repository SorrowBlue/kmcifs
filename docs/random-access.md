# Random Access & Streaming

Use `SmbRandomAccessFile` for workloads that move the file pointer back and forth while reading or writing, such as parsing video container indices or extracting archives. Modeled after `java.io.RandomAccessFile` in the standard JDK, it tracks the current offset (`position`) and supports `seek`, `read`, `readByte`, `write`, `length`, and resizing via `setLength`.

## Opening `SmbRandomAccessFile` and Modes

Pass a path and mode string to `SmbShare.openRandomAccessFile` or `SmbRandomAccessFile.open` to obtain an instance with the file already opened on the server. You can also instantiate `SmbRandomAccessFile` first and call `open()` later.

Four mode strings are supported, matching `java.io.RandomAccessFile`:

| Mode | `SmbRandomAccessMode` | Behavior and SMB2 Flags |
| :--- | :--- | :--- |
| `"r"` | `READ_ONLY` | Read-only (`FILE_OPEN`). Throws an exception if the file does not exist; calling any write method throws `IllegalStateException`. |
| `"rw"` | `READ_WRITE` | Read/write (`FILE_OPEN_IF`). Creates a new file if the target does not exist. |
| `"rws"` | `READ_WRITE_SYNC` | Adds `FILE_WRITE_THROUGH` to `"rw"`, requesting synchronous flushing to server storage on writes. |
| `"rwd"` | `READ_WRITE_DSYNC` | Opens with `FILE_WRITE_THROUGH` enabled, similar to `"rws"`. |

```kotlin
import com.sorrowblue.kmcifs.client.SmbRandomAccessFile

// Open directly from a share
val raf = share.openRandomAccessFile("media/movie.avi", mode = "r")

// Instantiate first and call open() explicitly
val writableRaf = SmbRandomAccessFile(share, "data/index.bin", mode = "rw")
writableRaf.open()
```

## Reading, Seeking, and Writing

The `position` property returns the current byte offset from the beginning of the file, and the `length` property returns the current file size. Both read in-memory metadata without triggering network I/O.

```kotlin
val raf = share.openRandomAccessFile("data/sample.bin", mode = "rw")
try {
    // Write at the current position (advances position by the number of bytes written)
    raf.write("RIFF".encodeToByteArray())
    raf.writeInt(0x12345678)
    raf.writeByte(0x7F)
    println("Current size: ${raf.length}, current position: ${raf.position}")

    // Seek back to the start and read primitives
    raf.seek(0L)
    val magic = ByteArray(4)
    raf.readFully(magic)
    val headerValue = raf.readInt()
    val flag: Byte = raf.readByte()

    // Seek to an arbitrary offset and read a slice
    raf.seek(4L)
    val buffer = ByteArray(16)
    val bytesRead = raf.read(buffer, 0, buffer.size) // Returns -1 at EOF

    // Truncate the file (if position > newLength, position is clamped to newLength)
    raf.setLength(4L)
} finally {
    raf.closeSuspend()
}
```

### EOF Behavior: `read()` vs. `readByte()`

Following the contract of `java.io.RandomAccessFile`, end-of-file (EOF) handling differs depending on the method called.

`read()` (single-byte read) and `read(b, off, len)` (buffer read) return `-1` without throwing an exception when called at EOF. By contrast, `readByte()`, `readUnsignedByte()`, `readShort()`, `readInt()`, `readLong()`, and `readFully()` throw `SmbEndOfFileException` if EOF is reached before all requested bytes have been read.

## Internal Read Buffering

Sending an individual SMB packet for every `readByte()` or small `read()` call would incur a full TCP round-trip time (RTT) per byte. `SmbRandomAccessFile` supports an in-memory read buffer to coalesce small reads.

When `readByte()` or a small `read()` is called and the requested offset is present in the buffer, the value is returned immediately from memory without network traffic. When an unbuffered offset is requested, up to `bufferSize` bytes starting at that offset are fetched in a single `SMB2 READ`. Conversely, large `read(b, off, len)` calls exceeding the buffer size read directly from the server into the caller's array to avoid extra memory copies.

Executing `write` or `setLength` immediately invalidates the internal read buffer so subsequent reads never return stale data. You can customize the buffer size or disable buffering (`bufferSize = 0`) via the third argument of `openRandomAccessFile(path, mode, bufferSize)`.
