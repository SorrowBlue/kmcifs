# ランダムアクセスとストリーミング

動画コンテナのインデックス解析やアーカイブファイルの展開など、ファイルポインタを前後に移動しながら読み書きを行う処理には `SmbRandomAccessFile` を使用する。JDK 標準の `java.io.RandomAccessFile` と同じ概念で設計されており、現在位置（`position`）の保持、`seek`、`read`、`readByte`、`write`、`length` の参照および `setLength` によるサイズ変更を備えている。

## `SmbRandomAccessFile` のオープンとモード指定

`SmbShare.openRandomAccessFile` または `SmbRandomAccessFile.open` にパスとモード文字列を渡すと、サーバー上でファイルを開いた状態のインスタンスが返る。インスタンスを先に生成してから任意のタイミングで `open()` を呼び出すこともできる。

モード文字列は Java の `RandomAccessFile` と同一の 4 種類を受け付ける。

| モード | `SmbRandomAccessMode` | 挙動と SMB2 フラグ |
| :--- | :--- | :--- |
| `"r"` | `READ_ONLY` | 読み取り専用（`FILE_OPEN`）。対象が存在しない場合は例外となり、書き込みメソッドを呼ぶと `IllegalStateException` を送出する。 |
| `"rw"` | `READ_WRITE` | 読み書き両用（`FILE_OPEN_IF`）。対象が存在しない場合は新規作成する。 |
| `"rws"` | `READ_WRITE_SYNC` | `"rw"` に加え `FILE_WRITE_THROUGH` を付与し、書き込み時にサーバー側ストレージへの同期フラッシュを要求する。 |
| `"rwd"` | `READ_WRITE_DSYNC` | `"rws"` と同様に `FILE_WRITE_THROUGH` を有効化してオープンする。 |

```kotlin
import com.sorrowblue.kmcifs.client.SmbRandomAccessFile

// 共有フォルダから直接オープンする
val raf = share.openRandomAccessFile("media/movie.avi", mode = "r")

// インスタンスを生成してから open() を呼ぶ場合
val writableRaf = SmbRandomAccessFile(share, "data/index.bin", mode = "rw")
writableRaf.open()
```

## 読み取り・シーク・書き込み

`position` プロパティは先頭からの現在オフセット（バイト単位）を返し、`length` プロパティは現在のファイルサイズを返す。どちらもメモリ上のメタデータを参照するためネットワーク通信は発生しない。

```kotlin
val raf = share.openRandomAccessFile("data/sample.bin", mode = "rw")
try {
    // 書き込み（現在位置から書き込まれ、書き込んだバイト数だけ position が進む）
    raf.write("RIFF".encodeToByteArray())
    raf.writeInt(0x12345678)
    raf.writeByte(0x7F)
    println("現在のサイズ: ${raf.length}, 現在位置: ${raf.position}")

    // 先頭へシークして読み取る
    raf.seek(0L)
    val magic = ByteArray(4)
    raf.readFully(magic)
    val headerValue = raf.readInt()
    val flag: Byte = raf.readByte()

    // 任意の位置へシークして部分読み取り
    raf.seek(4L)
    val buffer = ByteArray(16)
    val bytesRead = raf.read(buffer, 0, buffer.size) // EOF 時は -1

    // ファイルサイズを切り詰める（position > newLength の場合は position も丸められる）
    raf.setLength(4L)
} finally {
    raf.closeSuspend()
}
```

### `read()` と `readByte()` の終端（EOF）挙動の違い

`java.io.RandomAccessFile` の規約に合わせ、メソッドによってファイル末尾（EOF）到達時の扱いが異なる。

`read()`（1 バイト読み取り）および `read(b, off, len)`（バッファへの読み取り）は、すでに EOF に達している状態で呼び出されると例外を投げずに `-1` を返す。一方で `readByte()`、`readUnsignedByte()`、`readShort()`、`readInt()`、`readLong()`、`readFully()` は指定バイト数を読み切る前に EOF へ到達すると `SmbEndOfFileException` を送出する。

## 内部読み取りバッファの仕組み

SMB プロトコル上で `readByte()` や数バイト単位の `read()` をそのまま 1 回ずつパケット送信すると、1 バイト読むたびに TCP 往復遅延（RTT）が加算されて実用にならない。そのため `SmbRandomAccessFile` は既定で 64KB（`DEFAULT_BUFFER_SIZE`）のインメモリ読み取りバッファを持つ。

`readByte()` や小さな `read()` が呼ばれた際、要求オフセットがバッファ内に存在すればネットワーク通信を一切行わずにメモリから即座に値を返す。バッファ外のオフセットが要求された場合は、その位置から最大 64KB 分を 1 回の `SMB2 READ` でまとめて取得する。逆に 64KB 以上の大きな `read(b, off, len)` が要求された場合は、余計なメモリコピーを避けるためサーバーから直接呼び出し元の配列へ読み込む。

`write` や `setLength` が実行された際は内部バッファを即座に破棄するため、直後に同じ領域を読み直しても古いキャッシュが返ることはない。バッファサイズを変更したい場合やバッファリングを無効化したい場合（`bufferSize = 0`）は、`openRandomAccessFile(path, mode, bufferSize)` の第 3 引数で指定できる。
