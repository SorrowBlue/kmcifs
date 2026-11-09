# サンプルアプリケーション

リポジトリ内の `sample` モジュール群は、`kmcifs-client` を用いたファイルブラウジングとオンデマンド動画ストリーミングの実動リファレンス実装になっている。

## 共通モジュール (`sample`) の構成

UI 層を除くすべての処理は共通モジュール `sample` に集約されている。

接続設定の保存には `SmbCredentialCipher` を用いる。ホスト名、ポート番号、認証情報、暗号化ポリシー、最後に開いた共有名とディレクトリパスをシリアライズし、ランダムな 12 バイト IV と 16 バイト認証タグを付与した `AES-128-GCM` で暗号化してデバイス内に保存する。

数 GB を超える動画ファイルをダウンロード待ちなしで再生するため、`SmbRandomAccessStream` と `SmbHttpRangeServer` の 2 つを組み合わせている。`SmbRandomAccessStream` はファイルを 256KB の固定ブロック単位で分割管理し、最大 32MB（128 ブロック）のインメモリ LRU キャッシュを保持する。キャッシュロックとネットワーク通信ロックを分離しているため、キャッシュ済みの領域に対する読み取りはバックグラウンドの先読み通信を待たずに即座に返る。連続したブロックが要求された場合のみシーケンシャル再生と判定して裏で 1MB（4 ブロック）ずつの非同期プリフェッチを走らせ、コンテナ解析のための末尾シークなど単発のランダムアクセスでは無駄な先読みを行わない。

`SmbHttpRangeServer` は `ktor-network` を用いて `127.0.0.1` の空きポート上に軽量な HTTP 1.1 サーバーを立て、`Range: bytes=start-end` リクエストに対して `206 Partial Content` で `SmbRandomAccessStream` のデータをストリーム返却する。ローカルファイル記述子（`fd://`）ではなく HTTP Range サーバーを介することで、VLC などのメディアプレイヤーに「シーク可能だが高速ローカルディスクではない（`STREAM_CAN_FASTSEEK = false`）」と認識させ、9GB 超の OpenDML AVI 2.0 ファイルでもファイル全体のインデックス走査を行わせずに数秒で再生を開始させている。

## プラットフォーム別アプリケーション

### Android (`sample/androidApp`)

Jetpack Compose（Material 3）による 3 画面構成（接続設定画面・共有フォルダおよびディレクトリ一覧画面・ファイルビューア画面）のアプリケーション。接続情報は Android Keystore のハードウェア保護された `AES/GCM/NoPadding` 秘密鍵で暗号化して保存する。動画再生には `org.videolan.android:libvlc-all`（LibVLC）を組み込み、ローカル HTTP ストリーミングサーバー経由で H.264 / HEVC / MPEG-4 映像および Dolby AC3 / EAC3 / AAC 音声を再生する。

```bash
./kotlin build -m androidApp
```

### Windows ネイティブ GUI (`sample/windowsApp`)

Kotlin/Native（`mingwX64`）から Win32 API（`CreateWindowExW`）を直接呼び出すネイティブ GUI アプリケーション。`%APPDATA%\kmcifs\connection.enc` に暗号化された接続設定を保持し、共有フォルダ一覧とファイル一覧の 2 ペインリストボックス、テキストプレビューペイン、およびローカル HTTP Range ストリーミングサーバーを介した VLC・既定プレイヤー連携を備える。コマンドライン引数を渡して起動した場合は CLI モードとして動作する。

```powershell
.\kotlin.bat run -m windowsApp
```

### iOS (`sample/iosApp`)

Kotlin/Native から UIKit（`UINavigationController` / `UITableViewController`）と `AVPlayerViewController` を駆動し、Keychain（`SecItemAdd` / `SecItemCopyMatching`）と `SmbCredentialCipher` を組み合わせて接続情報を保護する。

### JVM / Linux / macOS CLI (`sample/jvmApp`, `sample/linuxApp`, `sample/macosApp`)

コマンドライン引数または環境変数（`SMB_HOST`, `SMB_USER`, `SMB_PASSWORD`, `SMB_SHARE` 等）を受け取り、共有フォルダ一覧の列挙、ディレクトリ探索、テキスト先頭プレビュー、動画ストリームのランダムアクセス検証を実行する。

```bash
./kotlin run -m jvmApp -- --host=192.168.1.100 --user=alice --password=secret --share=Public
```
