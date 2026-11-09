package com.sorrowblue.kmcifs.client.protocol

/**
 * 16-byte SMB2 file handle identifier (`[MS-SMB2] 2.2.14.1`), consisting of a
 * 64-bit [persistent] handle and a 64-bit [volatile] handle.
 */
data class SmbFileId(
    val persistent: ULong,
    val volatile: ULong,
) {
    companion object {
        /**
         * Sentinel `FileId` (`0xFFFFFFFFFFFFFFFF`, `0xFFFFFFFFFFFFFFFF`) used in Compounded Related
         * requests to reference the handle produced by a preceding `SMB2 CREATE` request (`[MS-SMB2] 3.2.4.1.4`).
         */
        val COMPOUND_RELATED = SmbFileId(
            persistent = 0xFFFF_FFFF_FFFF_FFFFuL,
            volatile = 0xFFFF_FFFF_FFFF_FFFFuL,
        )
    }
}

/**
 * File attribute bitmask constants (`[MS-FSCC] 2.6`).
 */
object SmbFileAttributes {
    const val READONLY: UInt = 0x00000001u
    const val HIDDEN: UInt = 0x00000002u
    const val SYSTEM: UInt = 0x00000004u
    const val DIRECTORY: UInt = 0x00000010u
    const val ARCHIVE: UInt = 0x00000020u
    const val NORMAL: UInt = 0x00000080u
    const val TEMPORARY: UInt = 0x00000100u
    const val REPARSE_POINT: UInt = 0x00000400u
}

/**
 * `DesiredAccess` bitmask constants for `SMB2 CREATE` requests (`[MS-SMB2] 2.2.13.1`).
 */
object SmbAccessMask {
    const val FILE_READ_DATA: UInt = 0x00000001u
    const val FILE_LIST_DIRECTORY: UInt = 0x00000001u
    const val FILE_WRITE_DATA: UInt = 0x00000002u
    const val FILE_APPEND_DATA: UInt = 0x00000004u
    const val FILE_READ_EA: UInt = 0x00000008u
    const val FILE_WRITE_EA: UInt = 0x00000010u
    const val FILE_EXECUTE: UInt = 0x00000020u
    const val FILE_READ_ATTRIBUTES: UInt = 0x00000080u
    const val FILE_WRITE_ATTRIBUTES: UInt = 0x00000100u
    const val DELETE: UInt = 0x00010000u
    const val READ_CONTROL: UInt = 0x00020000u
    const val WRITE_DAC: UInt = 0x00040000u
    const val WRITE_OWNER: UInt = 0x00080000u
    const val SYNCHRONIZE: UInt = 0x00100000u
    const val GENERIC_ALL: UInt = 0x10000000u
    const val GENERIC_EXECUTE: UInt = 0x20000000u
    const val GENERIC_WRITE: UInt = 0x40000000u
    const val GENERIC_READ: UInt = 0x80000000u

    val READ_DEFAULT: UInt = FILE_READ_DATA or FILE_READ_ATTRIBUTES or FILE_READ_EA or READ_CONTROL or SYNCHRONIZE
    val WRITE_DEFAULT: UInt = READ_DEFAULT or FILE_WRITE_DATA or FILE_APPEND_DATA or FILE_WRITE_ATTRIBUTES or FILE_WRITE_EA
    val DELETE_DEFAULT: UInt = DELETE or FILE_READ_ATTRIBUTES or SYNCHRONIZE
}

/**
 * `ShareAccess` (sharing mode) bitmask constants for `SMB2 CREATE` requests (`[MS-SMB2] 2.2.13`).
 */
object SmbShareAccess {
    /** Denies all concurrent open requests from other handles (exclusive access). */
    const val EXCLUSIVE: UInt = 0x00000000u
    const val FILE_SHARE_READ: UInt = 0x00000001u
    const val FILE_SHARE_WRITE: UInt = 0x00000002u
    const val FILE_SHARE_DELETE: UInt = 0x00000004u
    const val ALL: UInt = 0x00000007u
}

/**
 * `CreateDisposition` values for `SMB2 CREATE` requests (`[MS-SMB2] 2.2.13`).
 */
enum class SmbCreateDisposition(val code: UInt) {
    /** If the file already exists, supersede (replace) it; otherwise, create the file. */
    FILE_SUPERSEDE(0x00000000u),
    /** If the file already exists, open it; otherwise, fail the request. */
    FILE_OPEN(0x00000001u),
    /** If the file already exists, fail the request; otherwise, create the file. */
    FILE_CREATE(0x00000002u),
    /** If the file already exists, open it; otherwise, create the file. */
    FILE_OPEN_IF(0x00000003u),
    /** If the file already exists, open and overwrite (truncate) it; otherwise, fail the request. */
    FILE_OVERWRITE(0x00000004u),
    /** If the file already exists, open and overwrite (truncate) it; otherwise, create the file. */
    FILE_OVERWRITE_IF(0x00000005u),
}

/**
 * `CreateOptions` bitmask constants for `SMB2 CREATE` requests (`[MS-SMB2] 2.2.13`).
 */
object SmbCreateOptions {
    const val FILE_DIRECTORY_FILE: UInt = 0x00000001u
    const val FILE_WRITE_THROUGH: UInt = 0x00000002u
    const val FILE_SEQUENTIAL_ONLY: UInt = 0x00000004u
    const val FILE_SYNCHRONOUS_IO_NONALERT: UInt = 0x00000020u
    const val FILE_NON_DIRECTORY_FILE: UInt = 0x00000040u
    const val FILE_DELETE_ON_CLOSE: UInt = 0x00001000u
    const val FILE_OPEN_REPARSE_POINT: UInt = 0x00200000u
}

/**
 * Directory entry metadata returned by directory enumeration (`FileIdBothDirectoryInformation`).
 */
data class SmbDirectoryEntry(
    val name: String,
    val size: Long,
    val allocationSize: Long,
    val fileAttributes: UInt,
    val creationTimeMillis: Long,
    val lastAccessTimeMillis: Long,
    val lastWriteTimeMillis: Long,
    val changeTimeMillis: Long,
    val fileId: ULong,
) {
    val isDirectory: Boolean
        get() = (fileAttributes and SmbFileAttributes.DIRECTORY) != 0u

    val isReadOnly: Boolean
        get() = (fileAttributes and SmbFileAttributes.READONLY) != 0u

    val isHidden: Boolean
        get() = (fileAttributes and SmbFileAttributes.HIDDEN) != 0u
}

/**
 * Metadata for a single file or directory returned by `SMB2 CREATE` (`[SmbShare.stat]`).
 */
data class SmbFileMetadata(
    val size: Long,
    val allocationSize: Long,
    val fileAttributes: UInt,
    val creationTimeMillis: Long,
    val lastAccessTimeMillis: Long,
    val lastWriteTimeMillis: Long,
    val changeTimeMillis: Long,
) {
    val isDirectory: Boolean
        get() = (fileAttributes and SmbFileAttributes.DIRECTORY) != 0u

    val isReadOnly: Boolean
        get() = (fileAttributes and SmbFileAttributes.READONLY) != 0u

    val isHidden: Boolean
        get() = (fileAttributes and SmbFileAttributes.HIDDEN) != 0u
}

/**
 * Type of shared resource on an SMB server (`[MS-SRVS] 2.2.2.4`).
 */
enum class SmbShareType(val code: UInt) {
    DISKTREE(0u),
    PRINTQ(1u),
    DEVICE(2u),
    IPC(3u),
    UNKNOWN(0xFFu);

    companion object {
        fun fromRawType(rawType: UInt): SmbShareType {
            return when (rawType and 0x000000FFu) {
                0u -> DISKTREE
                1u -> PRINTQ
                2u -> DEVICE
                3u -> IPC
                else -> UNKNOWN
            }
        }
    }
}

/**
 * Information about a shared folder enumerated via DCE/RPC `NetrShareEnum`.
 */
data class SmbShareInfo(
    val name: String,
    val rawType: UInt,
    val comment: String,
) {
    val type: SmbShareType
        get() = SmbShareType.fromRawType(rawType)

    val isSpecialOrHidden: Boolean
        get() = (rawType and 0x80000000u) != 0u || name.endsWith('$')
}
