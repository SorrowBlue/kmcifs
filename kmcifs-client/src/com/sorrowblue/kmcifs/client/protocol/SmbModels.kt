package com.sorrowblue.kmcifs.client.protocol

/**
 * SMB2 ファイルハンドル識別子 (Persistent 8 bytes + Volatile 8 bytes = 16 bytes)。
 */
data class SmbFileId(
    val persistent: ULong,
    val volatile: ULong,
) {
    companion object {
        /** Compounded Related リクエストで直前の CREATE 結果を引き継ぐためのセンチネル FileId (`-1, -1`)。 */
        val COMPOUND_RELATED = SmbFileId(
            persistent = 0xFFFF_FFFF_FFFF_FFFFuL,
            volatile = 0xFFFF_FFFF_FFFF_FFFFuL,
        )
    }
}

/**
 * ファイル属性フラグ定数 (MS-FSCC 2.6)。
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
 * CREATE リクエストの DesiredAccess フラグ定数。
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
 * CREATE リクエストの ShareAccess（共有排他モード）フラグ定数。
 */
object SmbShareAccess {
    /** 他のプロセスからの一切のオープンを拒否する（完全排他ロック）。 */
    const val EXCLUSIVE: UInt = 0x00000000u
    const val FILE_SHARE_READ: UInt = 0x00000001u
    const val FILE_SHARE_WRITE: UInt = 0x00000002u
    const val FILE_SHARE_DELETE: UInt = 0x00000004u
    const val ALL: UInt = 0x00000007u
}

/**
 * CREATE リクエストの CreateDisposition 定数。
 */
enum class SmbCreateDisposition(val code: UInt) {
    /** 既存があれば置き換え、なければ新規作成。 */
    FILE_SUPERSEDE(0x00000000u),
    /** 既存を開く。存在しなければ失敗。 */
    FILE_OPEN(0x00000001u),
    /** 新規作成する。既に存在する場合は失敗。 */
    FILE_CREATE(0x00000002u),
    /** 既存があれば開き、なければ新規作成。 */
    FILE_OPEN_IF(0x00000003u),
    /** 既存を開いて上書き（サイズ0にトランケート）。存在しなければ失敗。 */
    FILE_OVERWRITE(0x00000004u),
    /** 既存があれば上書き、なければ新規作成。 */
    FILE_OVERWRITE_IF(0x00000005u),
}

/**
 * CREATE リクエストの CreateOptions フラグ定数。
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
 * ディレクトリ一覧取得で返される各ファイル・フォルダのエントリ情報。
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
 * 単一ファイルまたはディレクトリのメタデータ。
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
 * 共有フォルダの種類 (MS-SRVS 2.2.2.4)。
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
 * サーバー上の共有フォルダ情報 (`NetrShareEnum` 結果)。
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
