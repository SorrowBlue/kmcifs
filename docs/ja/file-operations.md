# ファイルとディレクトリ操作

共有フォルダへの接続は `client.connectShare(shareName)` で行う。返される `SmbShare` インスタンスは SMB2 の `TREE_CONNECT` セッションを保持し、相対パスを指定したファイル・ディレクトリ操作を提供する。パスの区切り文字はスラッシュ（`/`）とバックスラッシュ（`\`）のどちらを渡しても内部で正規化される。

## ディレクトリ走査とメタデータ取得

共有ルート直下の一覧を得るには `share.listDirectory("")` を呼び出す。内部では `FileIdBothDirectoryInformation`（Class 37）を用いた `SMB2 QUERY_DIRECTORY` をサーバーが `STATUS_NO_MORE_FILES` を返すまで繰り返し実行し、カレントディレクトリ（`.`）と親ディレクトリ（`..`）を除いたエントリ一覧を返す。

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

特定のパスが存在するかどうかの確認には `share.exists(path)`、サイズやタイムスタンプ・属性フラグの取得には `share.stat(path)` を使う。`exists` は `STATUS_OBJECT_NAME_NOT_FOUND` や `STATUS_OBJECT_PATH_NOT_FOUND`、`STATUS_NO_SUCH_FILE` を捕捉して `false` に変換し、権限不足（`STATUS_ACCESS_DENIED`）などの異常系はそのまま `SmbException` として送出する。

## 一括読み書き・作成・削除・リネーム

小さな設定ファイルやテキストファイルを丸ごと読み書きする用途には、`SmbShare` のユーティリティメソッドを直接呼び出すのが簡潔である。

```kotlin
// テキストの書き込み（overwrite = true なら FILE_OVERWRITE_IF）
share.writeText("config/settings.json", """{"theme":"dark"}""", overwrite = true)

// テキスト・バイト配列の読み取り
val json = share.readText("config/settings.json")
val rawBytes = share.readBytes("config/settings.json")

// 末尾への追記（ファイルがなければ新規作成）
share.appendBytes("logs/app.log", "Started\n".encodeToByteArray())

// ディレクトリ作成・リネーム・削除
share.createDirectory("archive")
share.rename("config/settings.json", "archive/settings.bak", replaceIfExists = true)
share.deleteFile("archive/settings.bak")
share.deleteDirectory("archive")
```

## 低レベルファイルハンドル (`SmbFile`) と排他ロック

Windows / SMB のアクセス権マスク（`SmbAccessMask`）、共有モード（`SmbShareAccess`）、生成オプション（`SmbCreateDisposition`）を細かく制御してファイルを開く場合は `share.openFile` を使う。

他プロセスからの同時オープン自体を拒否したい場合は `shareAccess = SmbShareAccess.EXCLUSIVE` を渡す。ファイルを開いたまま特定のバイト範囲だけを排他ロックまたは共有ロックしたい場合は、`SmbFile.lock` と `SmbFile.unlock`（`SMB2 LOCK`）を使用する。

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
    // 先頭 4096 バイトに対して排他ロックを取得（競合時は待機せず即座にエラーとする）
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
