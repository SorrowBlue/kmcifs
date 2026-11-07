package com.sorrowblue.kmcifs.sample

import com.sorrowblue.kmcifs.client.SmbEncryptionPolicy
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertNull

class SmbSampleTest {

    @Test
    fun credentialCipherEncryptsAndDecryptsRoundTrip() {
        val original = SmbSavedConnection(
            host = "192.168.10.25",
            port = 445,
            username = "admin",
            password = "P@ssw0rd!秘密",
            domain = "WORKGROUP",
            shareName = "MediaShare",
            directoryPath = "Videos/2026",
            encryptionPolicy = SmbEncryptionPolicy.REQUIRED,
        )
        val key = ByteArray(16) { (it * 7 + 3).toByte() }
        val iv = ByteArray(12) { (it + 1).toByte() }

        val encrypted = SmbCredentialCipher.encryptToBase64(original, key, iv)
        assertNotEquals(original.password, encrypted)

        val decrypted = SmbCredentialCipher.decryptFromBase64(encrypted, key)
        assertEquals(original, decrypted)
    }

    @Test
    fun credentialCipherRejectsWrongKey() {
        val original = SmbSavedConnection(
            host = "10.0.0.5",
            username = "user1",
            password = "secret",
        )
        val key1 = ByteArray(16) { 0x11 }
        val key2 = ByteArray(16) { 0x22 }

        val encrypted = SmbCredentialCipher.encryptToBase64(original, key1)
        assertFailsWith<IllegalStateException> {
            SmbCredentialCipher.decryptFromBase64(encrypted, key2)
        }
    }

    @Test
    fun previewTypeDetectsTextImageAndVideoExtensions() {
        assertEquals(SmbPreviewType.TEXT, SmbPreviewType.fromFileName("notes.txt"))
        assertEquals(SmbPreviewType.TEXT, SmbPreviewType.fromFileName("README.md"))
        assertEquals(SmbPreviewType.TEXT, SmbPreviewType.fromFileName("config.json"))
        assertEquals(SmbPreviewType.TEXT, SmbPreviewType.fromFileName("README"))

        assertEquals(SmbPreviewType.IMAGE, SmbPreviewType.fromFileName("photo.JPG"))
        assertEquals(SmbPreviewType.IMAGE, SmbPreviewType.fromFileName("diagram.png"))
        assertEquals(SmbPreviewType.IMAGE, SmbPreviewType.fromFileName("banner.webp"))

        assertEquals(SmbPreviewType.VIDEO, SmbPreviewType.fromFileName("movie.mp4"))
        assertEquals(SmbPreviewType.VIDEO, SmbPreviewType.fromFileName("clip.MKV"))
        assertEquals(SmbPreviewType.VIDEO, SmbPreviewType.fromFileName("capture.mov"))

        assertEquals(SmbPreviewType.OTHER, SmbPreviewType.fromFileName("archive.zip"))
    }

    @Test
    fun pathNavigationHelpersNormalizePaths() {
        assertEquals("folder/sub", SmbFormatUtils.joinPath("/folder/", "\\sub\\"))
        assertEquals("folder", SmbFormatUtils.parentPath("folder/sub"))
        assertEquals("", SmbFormatUtils.parentPath("folder"))
        assertNull(SmbFormatUtils.parentPath(""))
    }
}
