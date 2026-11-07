package com.sorrowblue.kmcifs.client.auth

/**
 * SMB サーバー接続に使用する認証情報。
 *
 * @property username ユーザー名（匿名・ゲスト接続時は空文字列）
 * @property password パスワード
 * @property domain ドメイン名またはワークグループ名（デフォルトは空文字列）
 * @property workstation クライアントのワークステーション名
 */
data class SmbCredentials(
    val username: String = "",
    val password: String = "",
    val domain: String = "",
    val workstation: String = "KMCIFS",
) {
    val isAnonymous: Boolean
        get() = username.isEmpty() && password.isEmpty()

    companion object {
        val Anonymous = SmbCredentials()
    }
}
