package com.sorrowblue.kmcifs.sample.android

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import com.sorrowblue.kmcifs.sample.SmbCredentialCipher
import com.sorrowblue.kmcifs.sample.SmbSavedConnection
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Android Keystore の AES-256-GCM 秘密鍵を用いて SMB 接続情報を暗号化し、
 * デバイス内の SharedPreferences へ保存・復元するクラス。
 */
class EncryptedConnectionStore(context: Context) {

    private val prefs = context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    /**
     * 保存済みの暗号化された接続情報が存在するかどうかを返す。
     */
    fun hasSavedConnection(): Boolean {
        return prefs.contains(KEY_CIPHERTEXT) && prefs.contains(KEY_IV)
    }

    /**
     * 接続情報を Android Keystore の秘密鍵で AES-GCM 暗号化してデバイスに保存する。
     */
    fun save(connection: SmbSavedConnection) {
        val secretKey = getOrCreateSecretKey()
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        cipher.updateAAD(AAD_BYTES)

        val plainBytes = SmbCredentialCipher.serialize(connection)
        val cipherBytes = cipher.doFinal(plainBytes)
        val iv = cipher.iv

        prefs.edit()
            .putString(KEY_IV, Base64.encodeToString(iv, Base64.NO_WRAP))
            .putString(KEY_CIPHERTEXT, Base64.encodeToString(cipherBytes, Base64.NO_WRAP))
            .apply()
    }

    /**
     * デバイスに保存されている暗号化データを復号し、接続情報を返す。
     * 未保存または復号失敗時は `null` を返す。
     */
    fun load(): SmbSavedConnection? {
        val ivBase64 = prefs.getString(KEY_IV, null) ?: return null
        val cipherBase64 = prefs.getString(KEY_CIPHERTEXT, null) ?: return null

        return runCatching {
            val iv = Base64.decode(ivBase64, Base64.NO_WRAP)
            val cipherBytes = Base64.decode(cipherBase64, Base64.NO_WRAP)
            val secretKey = getOrCreateSecretKey()

            val cipher = Cipher.getInstance(TRANSFORMATION)
            val spec = GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv)
            cipher.init(Cipher.DECRYPT_MODE, secretKey, spec)
            cipher.updateAAD(AAD_BYTES)

            val plainBytes = cipher.doFinal(cipherBytes)
            SmbCredentialCipher.deserialize(plainBytes)
        }.onFailure {
            clear()
        }.getOrNull()
    }

    /**
     * 保存されている接続情報を削除する。
     */
    fun clear() {
        prefs.edit()
            .remove(KEY_IV)
            .remove(KEY_CIPHERTEXT)
            .apply()
    }

    private fun getOrCreateSecretKey(): SecretKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply {
            load(null)
        }
        val existingEntry = keyStore.getEntry(KEY_ALIAS, null) as? KeyStore.SecretKeyEntry
        if (existingEntry != null) {
            return existingEntry.secretKey
        }

        val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        val spec = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .build()

        keyGenerator.init(spec)
        return keyGenerator.generateKey()
    }

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val KEY_ALIAS = "kmcifs_sample_connection_aes_key"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val GCM_TAG_LENGTH_BITS = 128

        private const val PREFS_NAME = "kmcifs_encrypted_connection_prefs"
        private const val KEY_IV = "encrypted_conn_iv"
        private const val KEY_CIPHERTEXT = "encrypted_conn_data"
        private val AAD_BYTES = "kmcifs.android.sample.v1".toByteArray(Charsets.UTF_8)
    }
}
