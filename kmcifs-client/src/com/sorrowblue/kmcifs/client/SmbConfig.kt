package com.sorrowblue.kmcifs.client

import com.sorrowblue.kmcifs.client.protocol.SmbCipherId
import com.sorrowblue.kmcifs.client.protocol.SmbDialect

/**
 * SMB3 暗号化（Transform Header による通信暗号化）の適用ポリシー。
 */
enum class SmbEncryptionPolicy {
    /**
     * サーバー（セッションまたは共有フォルダ）が暗号化を要求した場合、
     * または [SmbConfig.preferEncryption] が有効かつサーバーが SMB 3.x 暗号化に対応している場合に暗号化する。
     */
    NEGOTIATE,

    /**
     * 常に SMB 3.x パケット暗号化を強制する。サーバーが暗号化に非対応の場合は接続時に例外を送出する。
     */
    REQUIRED,

    /**
     * クライアントからは暗号化を行わない（サーバー側が暗号化必須の設定になっている場合はサーバーに拒否される）。
     */
    DISABLED,
}

/**
 * SMB クライアント接続設定。
 *
 * @property dialects ネゴシエーションで提示する SMB ダイアレクト一覧
 * @property ciphers SMB 3.1.1 ネゴシエーションで提示する暗号化アルゴリズムの優先順リスト
 * @property encryptionPolicy SMB3 暗号化の適用ポリシー
 * @property preferEncryption [SmbEncryptionPolicy.NEGOTIATE] 時にサーバーが暗号化をサポートしていれば自発的に暗号化を有効にするか
 * @property alwaysSign 暗号化されていないパケットに対して常に SMB 署名を付与するか
 * @property verifyServerSignatures サーバーから受信した署名付きパケットの署名を検証するか
 * @property queryDirectoryBufferSize ディレクトリ一覧取得 (`QUERY_DIRECTORY`) の1回あたりの要求バッファサイズ（バイト）
 * @property randomAccessBufferSize [SmbRandomAccessFile] の既定の読み取りバッファサイズ（バイト）
 * @property connectTimeoutMillis TCP ソケット接続タイムアウト（ミリ秒）
 * @property requestTimeoutMillis 各 SMB リクエストの応答待機タイムアウト（ミリ秒）
 */
data class SmbConfig(
    val dialects: List<SmbDialect> = listOf(
        SmbDialect.SMB_3_1_1,
        SmbDialect.SMB_3_0_2,
        SmbDialect.SMB_3_0_0,
        SmbDialect.SMB_2_1_0,
        SmbDialect.SMB_2_0_2,
    ),
    val ciphers: List<SmbCipherId> = listOf(
        SmbCipherId.AES_128_GCM,
        SmbCipherId.AES_128_CCM,
    ),
    val encryptionPolicy: SmbEncryptionPolicy = SmbEncryptionPolicy.NEGOTIATE,
    val preferEncryption: Boolean = false,
    val alwaysSign: Boolean = false,
    val verifyServerSignatures: Boolean = false,
    val queryDirectoryBufferSize: Int = 64 * 1024,
    val randomAccessBufferSize: Int = SmbRandomAccessFile.DEFAULT_BUFFER_SIZE,
    val connectTimeoutMillis: Long = 10_000L,
    val requestTimeoutMillis: Long = 30_000L,
)
