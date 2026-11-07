# 接続・認証・暗号化

SMB サーバーとの接続は `SmbClient.connect` から開始する。TCP 接続の確立（既定ポート `445`、`TCP_NODELAY` 有効）、`SMB2 NEGOTIATE` によるプロトコルダイアレクトの決定、`SMB2 SESSION_SETUP` の 2 往復による NTLMv2 認証までがこの呼び出し内で完了する。

## 認証情報の指定

ユーザー名・パスワード・ドメイン（またはワークグループ名）は `SmbCredentials` に格納する。ドメイン環境でない NAS やスタンドアロン Windows 共有では `domain` を空文字列または `"WORKGROUP"` のままにしておけばよい。認証を伴わないゲスト共有へ接続する場合は `SmbCredentials.Guest` または `SmbCredentials.Anonymous` を渡す。

```kotlin
import com.sorrowblue.kmcifs.client.SmbClient
import com.sorrowblue.kmcifs.client.auth.SmbCredentials

// NTLMv2 認証
val credentials = SmbCredentials(
    username = "mediauser",
    password = "MyPassword123",
    domain = "WORKGROUP",
)

// ゲスト接続
val guestCredentials = SmbCredentials.Guest
```

## 署名と暗号化のトレードオフ (`SmbConfig`)

SMB 3.x では通信保護としてパケット単位の署名（`AES-128-CMAC`）と、Transform Header を用いたペイロード全体の暗号化（`AES-128-GCM` / `AES-128-CCM`）の 2 段階が存在する。`kmcifs-client` はクロスプラットフォームの一貫性を優先して AES 演算を純粋な Kotlin コードで実装しているため、この設定は通信速度に直結する。

MS-SMB2 仕様（3.3.5.7）により、SMB 3.1.1 の `TREE_CONNECT` などのリクエストは「暗号化されていない場合は必ず署名されていなければならない」。これを満たさないリクエストに対して Windows Server や Samba は `STATUS_ACCESS_DENIED` を返す。一方でクライアントから送信する `READ` リクエスト自体はわずか 113 バイトであり、ここに `AES-128-CMAC` 署名を付ける計算コストは無視できるほど小さい。これに対し、サーバーから返ってくる 256KB の `READ` レスポンス全体をソフトウェア実装の `AES-128-GCM` で毎ブロック復号・検証すると、動画ストリーミングのような高帯域通信では CPU がボトルネックになる。

この特性を踏まえ、`SmbConfig` では以下のポリシーを使い分ける。

```kotlin
import com.sorrowblue.kmcifs.client.SmbConfig
import com.sorrowblue.kmcifs.client.SmbEncryptionPolicy

// 高スループット設定（LAN 内の動画ストリーミングや大容量転送向け）
val streamingConfig = SmbConfig(
    encryptionPolicy = SmbEncryptionPolicy.NEGOTIATE,
    preferEncryption = false,
    alwaysSign = true,
    verifyServerSignatures = false,
)

// 完全暗号化設定（機密文書や信頼できないネットワーク経路向け）
val strictEncryptedConfig = SmbConfig(
    encryptionPolicy = SmbEncryptionPolicy.REQUIRED,
    preferEncryption = true,
)
```

`SmbEncryptionPolicy.NEGOTIATE` かつ `preferEncryption = false` に設定すると、SMB 3.1.1 の Encryption Context 自体はネゴシエートしてサーバーや共有フォルダ側が暗号化を強制（`SMB2_SHAREFLAG_ENCRYPT_DATA`）している場合にのみ暗号化を有効化し、通常の共有フォルダでは送信パケットの署名のみで高速に通信する。暗号化が強制された環境でのみ接続を許可したい場合は `SmbEncryptionPolicy.REQUIRED` を指定する。このときサーバーが SMB 3.x 暗号化に対応していなければ、セッション確立時点で `SmbException` が送出される。

## 共有フォルダ一覧の列挙 (`listShares`)

サーバー上に公開されている共有フォルダ一覧は `client.listShares()` で取得できる。内部では管理用共有 `IPC$` に `TREE_CONNECT` し、名前付きパイプ `srvsvc` を開いて DCE/RPC の `Bind` と `NetrShareEnum`（Level 1）を実行する。

```kotlin
val shares = client.listShares(includeHidden = false)
for (share in shares) {
    println("名前: ${share.name}, 種別: ${share.type}, コメント: ${share.comment}")
}
```

`includeHidden = false`（既定値）では `IPC$` や `ADMIN$`、`C$` のように末尾に `$` が付く管理用・隠し共有およびタイプフラグに非表示ビットが立っている共有を除外し、通常のディスク共有（`SmbShareType.DISKTREE`）などを返す。隠し共有を含めてすべて取得したい場合は `includeHidden = true` を渡す。
