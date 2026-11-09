package com.sorrowblue.kmcifs.client.auth

/**
 * Authentication credentials used to establish an SMB session.
 *
 * @property username Account username, or an empty string for anonymous/guest sessions.
 * @property password Account password.
 * @property domain Active Directory domain or workgroup name (defaults to an empty string).
 * @property workstation Client workstation name sent during NTLMSSP negotiation.
 */
data class SmbCredentials(
    val username: String = "",
    val password: String = "",
    val domain: String = "",
    val workstation: String = "KMCIFS",
) {
    /** Whether both [username] and [password] are empty, indicating an anonymous session. */
    val isAnonymous: Boolean
        get() = username.isEmpty() && password.isEmpty()

    companion object {
        /** Credentials instance for anonymous login. */
        val Anonymous = SmbCredentials()
    }
}
