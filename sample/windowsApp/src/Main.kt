@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

import com.sorrowblue.kmcifs.client.SmbEncryptionPolicy
import com.sorrowblue.kmcifs.client.protocol.SmbDirectoryEntry
import com.sorrowblue.kmcifs.client.protocol.SmbShareInfo
import com.sorrowblue.kmcifs.sample.SmbBrowserSession
import com.sorrowblue.kmcifs.sample.SmbCredentialCipher
import com.sorrowblue.kmcifs.sample.SmbFormatUtils
import com.sorrowblue.kmcifs.sample.SmbHttpRangeServer
import com.sorrowblue.kmcifs.sample.SmbPreviewType
import com.sorrowblue.kmcifs.sample.SmbSampleRunner
import com.sorrowblue.kmcifs.sample.SmbSavedConnection
import kotlinx.cinterop.ByteVar
import kotlinx.cinterop.COpaquePointer
import kotlinx.cinterop.CPointer
import kotlinx.cinterop.UByteVar
import kotlinx.cinterop.ULongVar
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.alloc
import kotlinx.cinterop.allocArray
import kotlinx.cinterop.convert
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.staticCFunction
import kotlinx.cinterop.toCPointer
import kotlinx.cinterop.toKString
import kotlinx.cinterop.toKStringFromUtf16
import kotlinx.cinterop.usePinned
import kotlinx.cinterop.value
import kotlinx.cinterop.wcstr
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import platform.posix.fclose
import platform.posix.fopen
import platform.posix.fread
import platform.posix.fseek
import platform.posix.ftell
import platform.posix.fwrite
import platform.posix.getenv
import platform.posix.remove
import platform.posix.SEEK_END
import platform.posix.SEEK_SET
import platform.windows.*
import kotlin.random.Random

private const val IDC_EDIT_HOST = 101
private const val IDC_EDIT_PORT = 102
private const val IDC_EDIT_USER = 103
private const val IDC_EDIT_PASS = 104
private const val IDC_EDIT_DOMAIN = 105
private const val IDC_EDIT_SHARE = 106
private const val IDC_COMBO_POLICY = 107
private const val IDC_CHECK_SAVE = 108

private const val IDC_BTN_CONNECT = 201
private const val IDC_BTN_OPEN_SHARE = 202
private const val IDC_BTN_CLEAR_SAVED = 203
private const val IDC_BTN_UP = 204
private const val IDC_BTN_REFRESH = 205
private const val IDC_BTN_OPEN_ITEM = 206
private const val IDC_BTN_STREAM_EXTERNAL = 207

private const val IDC_LIST_SHARES = 301
private const val IDC_LIST_ENTRIES = 302
private const val IDC_EDIT_PREVIEW = 303
private const val IDC_STATIC_STATUS = 304
private const val IDC_STATIC_PATH = 305

private val WM_APP_RUN_UI = (WM_APP + 1).toUInt()

fun main(args: Array<String>) {
    if (args.isNotEmpty()) {
        runBlocking {
            SmbSampleRunner.runCli("Windows (mingwX64)", args)
        }
        return
    }
    WindowsSmbGuiApp.run()
}

private object WindowsEncryptedConnectionStore {
    private val baseDir: String by lazy {
        val appData = getenv("APPDATA")?.toKString()?.takeIf { it.isNotBlank() } ?: "."
        val dir = "$appData\\kmcifs"
        CreateDirectoryW(dir, null)
        dir
    }

    private val keyPath: String get() = "$baseDir\\master.key"
    private val dataPath: String get() = "$baseDir\\connection.enc"

    fun load(): SmbSavedConnection? = runCatching {
        val encrypted = readFileBytes(dataPath) ?: return null
        if (encrypted.isEmpty()) return null
        val key = getOrCreateKey()
        SmbCredentialCipher.decryptFromBase64(encrypted.decodeToString(), key)
    }.getOrNull()

    fun save(connection: SmbSavedConnection) {
        runCatching {
            val key = getOrCreateKey()
            val encryptedBase64 = SmbCredentialCipher.encryptToBase64(connection, key)
            writeFileBytes(dataPath, encryptedBase64.encodeToByteArray())
        }
    }

    fun clear() {
        remove(dataPath)
    }

    private fun getOrCreateKey(): ByteArray {
        val existing = readFileBytes(keyPath)
        if (existing != null && existing.size == 16) {
            return existing
        }
        val created = Random.Default.nextBytes(16)
        writeFileBytes(keyPath, created)
        return created
    }

    private fun readFileBytes(path: String): ByteArray? {
        val file = fopen(path, "rb") ?: return null
        try {
            fseek(file, 0, SEEK_END)
            val size = ftell(file)
            if (size <= 0) return null
            fseek(file, 0, SEEK_SET)
            val buffer = ByteArray(size)
            buffer.usePinned { pinned ->
                fread(pinned.addressOf(0), 1u, size.toULong(), file)
            }
            return buffer
        } finally {
            fclose(file)
        }
    }

    private fun writeFileBytes(path: String, data: ByteArray) {
        val file = fopen(path, "wb") ?: return
        try {
            if (data.isNotEmpty()) {
                data.usePinned { pinned ->
                    fwrite(pinned.addressOf(0), 1u, data.size.toULong(), file)
                }
            }
        } finally {
            fclose(file)
        }
    }
}

private sealed class BrowserListItem {
    data object ParentDir : BrowserListItem()
    data class Folder(val entry: SmbDirectoryEntry) : BrowserListItem()
    data class File(val entry: SmbDirectoryEntry, val previewType: SmbPreviewType) : BrowserListItem()
}

private object WindowsSmbGuiApp {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val session = SmbBrowserSession()

    private val uiQueueMutex = kotlinx.coroutines.sync.Mutex()
    private val uiTasks = ArrayDeque<() -> Unit>()

    private var mainHwnd: HWND? = null
    private var uiFont: HFONT? = null
    private var monoFont: HFONT? = null

    private var hEditHost: HWND? = null
    private var hEditPort: HWND? = null
    private var hEditUser: HWND? = null
    private var hEditPass: HWND? = null
    private var hEditDomain: HWND? = null
    private var hEditShare: HWND? = null
    private var hComboPolicy: HWND? = null
    private var hCheckSave: HWND? = null

    private var hListShares: HWND? = null
    private var hListEntries: HWND? = null
    private var hEditPreview: HWND? = null
    private var hStaticStatus: HWND? = null
    private var hStaticPath: HWND? = null

    private var currentShares: List<SmbShareInfo> = emptyList()
    private var currentShareName: String = ""
    private var currentDirectoryPath: String = ""
    private var currentListItems: List<BrowserListItem> = emptyList()

    private var activeHttpServer: SmbHttpRangeServer? = null
    private var streamMonitorJob: Job? = null

    fun run() = memScoped {
        val hInstance = GetModuleHandleW(null)
        val className = "KmcifsWin32GuiClass"

        val wc = alloc<WNDCLASSEXW>()
        wc.cbSize = kotlinx.cinterop.sizeOf<WNDCLASSEXW>().toUInt()
        wc.style = (CS_HREDRAW or CS_VREDRAW).toUInt()
        wc.lpfnWndProc = staticCFunction(::windowProc)
        wc.hInstance = hInstance
        wc.hCursor = LoadCursorW(null, IDC_ARROW)
        wc.hbrBackground = GetSysColorBrush(COLOR_BTNFACE)
        wc.lpszClassName = className.wcstr.ptr

        val atom = RegisterClassExW(wc.ptr)
        if (atom == 0u.toUShort()) {
            println("RegisterClassExW failed: error=${GetLastError()}")
            return@memScoped
        }

        val hwnd = CreateWindowExW(
            dwExStyle = 0u,
            lpClassName = className,
            lpWindowName = "kmcifs SMB Browser & Video Streamer (Windows Native)",
            dwStyle = (WS_OVERLAPPEDWINDOW or WS_VISIBLE).toUInt(),
            X = CW_USEDEFAULT,
            Y = CW_USEDEFAULT,
            nWidth = 1080,
            nHeight = 760,
            hWndParent = null,
            hMenu = null,
            hInstance = hInstance,
            lpParam = null,
        )
        if (hwnd == null) {
            println("CreateWindowExW failed: error=${GetLastError()}")
            return@memScoped
        }

        mainHwnd = hwnd
        ShowWindow(hwnd, SW_SHOW)
        UpdateWindow(hwnd)
        println("Windows GUI started successfully (HWND=$hwnd)")
        platform.posix.fflush(null)

        val msg = alloc<MSG>()
        while (GetMessageW(msg.ptr, null, 0u, 0u) > 0) {
            if (IsDialogMessageW(hwnd, msg.ptr) == 0) {
                TranslateMessage(msg.ptr)
                DispatchMessageW(msg.ptr)
            }
        }
    }

    fun postToUi(block: () -> Unit) {
        runBlocking {
            uiQueueMutex.lock()
            try {
                uiTasks.addLast(block)
            } finally {
                uiQueueMutex.unlock()
            }
        }
        mainHwnd?.let { PostMessageW(it, WM_APP_RUN_UI, 0u, 0L) }
    }

    fun drainUiTasks() {
        while (true) {
            val task = runBlocking {
                uiQueueMutex.lock()
                try {
                    uiTasks.removeFirstOrNull()
                } finally {
                    uiQueueMutex.unlock()
                }
            } ?: break
            runCatching { task() }
        }
    }

    fun onCreate(hwnd: HWND) {
        val hInst = GetModuleHandleW(null)
        uiFont = CreateFontW(
            cHeight = -15,
            cWidth = 0,
            cEscapement = 0,
            cOrientation = 0,
            cWeight = FW_NORMAL,
            bItalic = 0u,
            bUnderline = 0u,
            bStrikeOut = 0u,
            iCharSet = DEFAULT_CHARSET.toUInt(),
            iOutPrecision = OUT_DEFAULT_PRECIS.toUInt(),
            iClipPrecision = CLIP_DEFAULT_PRECIS.toUInt(),
            iQuality = CLEARTYPE_QUALITY.toUInt(),
            iPitchAndFamily = DEFAULT_PITCH.toUInt(),
            pszFaceName = "Yu Gothic UI",
        )
        monoFont = CreateFontW(
            cHeight = -14,
            cWidth = 0,
            cEscapement = 0,
            cOrientation = 0,
            cWeight = FW_NORMAL,
            bItalic = 0u,
            bUnderline = 0u,
            bStrikeOut = 0u,
            iCharSet = DEFAULT_CHARSET.toUInt(),
            iOutPrecision = OUT_DEFAULT_PRECIS.toUInt(),
            iClipPrecision = CLIP_DEFAULT_PRECIS.toUInt(),
            iQuality = CLEARTYPE_QUALITY.toUInt(),
            iPitchAndFamily = FIXED_PITCH.toUInt(),
            pszFaceName = "Consolas",
        )

        // Row 1: Host, Port, User, Pass
        createLabel(hwnd, hInst, "ホスト / IP:", 16, 16, 80, 24)
        hEditHost = createEdit(hwnd, hInst, IDC_EDIT_HOST, "192.168.1.1", 98, 14, 170, 26)

        createLabel(hwnd, hInst, "Port:", 280, 16, 40, 24)
        hEditPort = createEdit(hwnd, hInst, IDC_EDIT_PORT, "445", 322, 14, 65, 26)

        createLabel(hwnd, hInst, "ユーザー:", 400, 16, 70, 24)
        hEditUser = createEdit(hwnd, hInst, IDC_EDIT_USER, "", 472, 14, 150, 26)

        createLabel(hwnd, hInst, "パスワード:", 635, 16, 80, 24)
        hEditPass = createEdit(hwnd, hInst, IDC_EDIT_PASS, "", 718, 14, 160, 26, isPassword = true)

        // Row 2: Domain, Share, Policy, Save Check
        createLabel(hwnd, hInst, "ドメイン:", 16, 50, 80, 24)
        hEditDomain = createEdit(hwnd, hInst, IDC_EDIT_DOMAIN, "", 98, 48, 140, 26)

        createLabel(hwnd, hInst, "共有名:", 252, 50, 60, 24)
        hEditShare = createEdit(hwnd, hInst, IDC_EDIT_SHARE, "", 314, 48, 150, 26)

        createLabel(hwnd, hInst, "暗号化:", 478, 50, 58, 24)
        hComboPolicy = CreateWindowExW(
            0u, "COMBOBOX", "",
            (WS_CHILD or WS_VISIBLE or WS_TABSTOP or CBS_DROPDOWNLIST).toUInt(),
            538, 48, 145, 160,
            hwnd, IDC_COMBO_POLICY.toLong().toCPointer(), hInst, null,
        )?.also { cb ->
            applyFont(cb, uiFont)
            addComboItem(cb, "NEGOTIATE (自動)")
            addComboItem(cb, "REQUIRED (必須)")
            addComboItem(cb, "DISABLED (無効)")
            SendMessageW(cb, CB_SETCURSEL.toUInt(), 0u, 0L)
        }

        hCheckSave = CreateWindowExW(
            0u, "BUTTON", "接続情報を暗号化保存",
            (WS_CHILD or WS_VISIBLE or WS_TABSTOP or BS_AUTOCHECKBOX).toUInt(),
            700, 48, 190, 26,
            hwnd, IDC_CHECK_SAVE.toLong().toCPointer(), hInst, null,
        )?.also { chk ->
            applyFont(chk, uiFont)
            SendMessageW(chk, BM_SETCHECK.toUInt(), BST_CHECKED.toULong(), 0L)
        }

        // Row 3: Action Buttons
        createButton(hwnd, hInst, IDC_BTN_CONNECT, "1. サーバー接続・共有取得", 16, 84, 200, 32)
        createButton(hwnd, hInst, IDC_BTN_OPEN_SHARE, "2. 共有フォルダを開く", 226, 84, 175, 32)
        createButton(hwnd, hInst, IDC_BTN_UP, "↑ 親フォルダへ", 412, 84, 130, 32)
        createButton(hwnd, hInst, IDC_BTN_REFRESH, "再読み込み", 552, 84, 110, 32)
        createButton(hwnd, hInst, IDC_BTN_CLEAR_SAVED, "保存情報を削除", 672, 84, 135, 32)

        // Row 4: Current Path
        hStaticPath = createLabel(hwnd, hInst, "現在の場所: (未接続)", 16, 126, 1020, 22)

        // Main Split Area:
        // Left Top: Shares List
        createLabel(hwnd, hInst, "共有フォルダ一覧 (ダブルクリックで接続):", 16, 154, 420, 20)
        hListShares = CreateWindowExW(
            WS_EX_CLIENTEDGE.toUInt(), "LISTBOX", "",
            (WS_CHILD or WS_VISIBLE or WS_VSCROLL or WS_TABSTOP or LBS_NOTIFY).toUInt(),
            16, 176, 440, 125,
            hwnd, IDC_LIST_SHARES.toLong().toCPointer(), hInst, null,
        )?.also { applyFont(it, uiFont) }

        // Left Bottom: Folders & Files List
        createLabel(hwnd, hInst, "フォルダ・ファイル一覧 (ダブルクリックで開く / 再生):", 16, 308, 440, 20)
        hListEntries = CreateWindowExW(
            WS_EX_CLIENTEDGE.toUInt(), "LISTBOX", "",
            (WS_CHILD or WS_VISIBLE or WS_VSCROLL or WS_HSCROLL or WS_TABSTOP or LBS_NOTIFY).toUInt(),
            16, 330, 440, 315,
            hwnd, IDC_LIST_ENTRIES.toLong().toCPointer(), hInst, null,
        )?.also { applyFont(it, uiFont) }

        createButton(hwnd, hInst, IDC_BTN_OPEN_ITEM, "選択項目を開く / プレビュー", 16, 650, 215, 32)
        createButton(hwnd, hInst, IDC_BTN_STREAM_EXTERNAL, "外部プレイヤーでストリーミング再生", 241, 650, 215, 32)

        // Right Pane: File Content / Streaming Status Preview
        createLabel(hwnd, hInst, "ファイルプレビュー / ストリーミング状態:", 472, 154, 560, 20)
        hEditPreview = CreateWindowExW(
            WS_EX_CLIENTEDGE.toUInt(), "EDIT",
            "SMB サーバーへ接続すると、共有フォルダ一覧とファイル一覧が表示されます。\r\n" +
                "・テキストファイル: このペイン内に内容を表示します。\r\n" +
                "・動画 / 画像ファイル: ローカル HTTP Range ストリーミングサーバー (http://127.0.0.1) を起動し、\r\n" +
                "  全量ダウンロードなしで VLC / 既定プレイヤーからオンデマンド再生します。",
            (WS_CHILD or WS_VISIBLE or WS_VSCROLL or WS_HSCROLL or ES_MULTILINE or ES_AUTOVSCROLL or ES_READONLY).toUInt(),
            472, 176, 575, 506,
            hwnd, IDC_EDIT_PREVIEW.toLong().toCPointer(), hInst, null,
        )?.also { applyFont(it, monoFont) }

        // Status Bar at Bottom
        hStaticStatus = createLabel(hwnd, hInst, "準備完了", 16, 692, 1030, 24)

        // Restore saved encrypted connection if present
        val saved = WindowsEncryptedConnectionStore.load()
        if (saved != null) {
            applySavedConnectionToUi(saved)
            setStatus("暗号化保存された接続設定 (${saved.host}:${saved.port}) を復元しました。")
        }
    }

    private fun applySavedConnectionToUi(saved: SmbSavedConnection) {
        SetWindowTextW(hEditHost, saved.host)
        SetWindowTextW(hEditPort, saved.port.toString())
        SetWindowTextW(hEditUser, saved.username)
        SetWindowTextW(hEditPass, saved.password)
        SetWindowTextW(hEditDomain, saved.domain)
        SetWindowTextW(hEditShare, saved.shareName)
        currentDirectoryPath = saved.directoryPath
        val policyIdx = when (saved.encryptionPolicy) {
            SmbEncryptionPolicy.NEGOTIATE -> 0
            SmbEncryptionPolicy.REQUIRED -> 1
            SmbEncryptionPolicy.DISABLED -> 2
        }
        hComboPolicy?.let { SendMessageW(it, CB_SETCURSEL.toUInt(), policyIdx.toULong(), 0L) }
    }

    private fun readConnectionFromUi(): SmbSavedConnection {
        val host = getControlText(hEditHost).trim()
        val port = getControlText(hEditPort).trim().toIntOrNull() ?: 445
        val user = getControlText(hEditUser).trim()
        val pass = getControlText(hEditPass)
        val domain = getControlText(hEditDomain).trim()
        val share = getControlText(hEditShare).trim()
        val policySel = hComboPolicy?.let { SendMessageW(it, CB_GETCURSEL.toUInt(), 0u, 0L).toInt() } ?: 0
        val policy = when (policySel) {
            1 -> SmbEncryptionPolicy.REQUIRED
            2 -> SmbEncryptionPolicy.DISABLED
            else -> SmbEncryptionPolicy.NEGOTIATE
        }
        return SmbSavedConnection(
            host = host,
            port = port,
            username = user,
            password = pass,
            domain = domain,
            shareName = share,
            directoryPath = currentDirectoryPath,
            encryptionPolicy = policy,
        )
    }

    private fun isSaveChecked(): Boolean {
        val check = hCheckSave?.let { SendMessageW(it, BM_GETCHECK.toUInt(), 0u, 0L).toInt() } ?: BST_CHECKED
        return check == BST_CHECKED
    }

    private fun persistIfEnabled(cfg: SmbSavedConnection) {
        if (isSaveChecked()) {
            WindowsEncryptedConnectionStore.save(cfg)
        }
    }

    fun onCommand(id: Int, notifyCode: Int) {
        when (id) {
            IDC_BTN_CONNECT -> connectAndListShares()
            IDC_BTN_OPEN_SHARE -> {
                val share = getControlText(hEditShare).trim()
                if (share.isEmpty()) {
                    setStatus("共有名を入力するか、共有フォルダ一覧から選択してください。")
                } else {
                    loadDirectory(share, "")
                }
            }
            IDC_BTN_CLEAR_SAVED -> {
                WindowsEncryptedConnectionStore.clear()
                setStatus("暗号化保存された接続情報を削除しました。")
            }
            IDC_BTN_UP -> {
                val parent = SmbFormatUtils.parentPath(currentDirectoryPath)
                if (currentShareName.isNotEmpty() && parent != null) {
                    loadDirectory(currentShareName, parent)
                }
            }
            IDC_BTN_REFRESH -> {
                if (currentShareName.isNotEmpty()) {
                    loadDirectory(currentShareName, currentDirectoryPath)
                } else {
                    connectAndListShares()
                }
            }
            IDC_BTN_OPEN_ITEM -> openSelectedEntry(forceExternalStream = false)
            IDC_BTN_STREAM_EXTERNAL -> openSelectedEntry(forceExternalStream = true)
            IDC_LIST_SHARES -> {
                if (notifyCode == LBN_SELCHANGE || notifyCode == LBN_DBLCLK) {
                    val idx = hListShares?.let { SendMessageW(it, LB_GETCURSEL.toUInt(), 0u, 0L).toInt() } ?: -1
                    val selected = currentShares.getOrNull(idx)
                    if (selected != null) {
                        SetWindowTextW(hEditShare, selected.name)
                        if (notifyCode == LBN_DBLCLK) {
                            loadDirectory(selected.name, "")
                        }
                    }
                }
            }
            IDC_LIST_ENTRIES -> {
                if (notifyCode == LBN_DBLCLK) {
                    openSelectedEntry(forceExternalStream = false)
                }
            }
        }
    }

    private fun connectAndListShares() {
        val cfg = readConnectionFromUi()
        if (cfg.host.isBlank()) {
            setStatus("エラー: ホスト名または IP アドレスを入力してください。")
            return
        }
        persistIfEnabled(cfg)
        setStatus("SMB サーバー ${cfg.host}:${cfg.port} へ接続中...")

        scope.launch {
            val result = runCatching {
                val summary = session.connect(cfg)
                val shares = runCatching { session.listShares(includeHidden = false) }.getOrElse { emptyList() }
                summary to shares
            }
            postToUi {
                result.fold(
                    onSuccess = { (summary, shares) ->
                        currentShares = shares
                        hListShares?.let { lb ->
                            SendMessageW(lb, LB_RESETCONTENT.toUInt(), 0u, 0L)
                            for (s in shares) {
                                val label = if (s.comment.isNotBlank()) "${s.name}  (${s.comment})" else s.name
                                addListItem(lb, label)
                            }
                        }
                        val encText = if (summary.isEncrypted) "暗号化あり (${summary.negotiatedCipher})" else "署名モード"
                        setStatus("接続成功: ${summary.host}:${summary.port} [${summary.negotiatedDialect}, $encText] - 共有 ${shares.size} 件")

                        val initialShare = cfg.shareName.ifBlank { shares.firstOrNull()?.name.orEmpty() }
                        if (initialShare.isNotBlank()) {
                            SetWindowTextW(hEditShare, initialShare)
                            loadDirectory(initialShare, cfg.directoryPath)
                        }
                    },
                    onFailure = { e ->
                        setStatus("接続エラー: ${e.message ?: e::class.simpleName}")
                        setPreviewText("接続エラーが発生しました:\r\n${e.stackTraceToString()}")
                    },
                )
            }
        }
    }

    private fun loadDirectory(shareName: String, path: String) {
        val cfg = readConnectionFromUi().copy(shareName = shareName, directoryPath = path)
        if (cfg.host.isBlank()) {
            setStatus("エラー: ホスト名または IP アドレスを入力してください。")
            return
        }
        persistIfEnabled(cfg)
        setStatus("//${cfg.host}/$shareName/$path の一覧を取得中...")

        scope.launch {
            val result = runCatching {
                session.connect(cfg)
                session.listDirectory(shareName, path)
            }
            postToUi {
                result.fold(
                    onSuccess = { listing ->
                        currentShareName = listing.shareName
                        currentDirectoryPath = listing.directoryPath
                        val displayPath = if (listing.directoryPath.isEmpty()) {
                            "//${listing.connection.host}/${listing.shareName}/"
                        } else {
                            "//${listing.connection.host}/${listing.shareName}/${listing.directoryPath}"
                        }
                        SetWindowTextW(hStaticPath, "現在の場所: $displayPath  (フォルダ ${listing.folders.size} 件 / ファイル ${listing.files.size} 件)")

                        val items = mutableListOf<BrowserListItem>()
                        if (listing.directoryPath.isNotEmpty()) {
                            items.add(BrowserListItem.ParentDir)
                        }
                        for (folder in listing.folders) {
                            items.add(BrowserListItem.Folder(folder))
                        }
                        for (file in listing.files) {
                            items.add(BrowserListItem.File(file, SmbPreviewType.fromFileName(file.name)))
                        }
                        currentListItems = items

                        hListEntries?.let { lb ->
                            SendMessageW(lb, LB_RESETCONTENT.toUInt(), 0u, 0L)
                            for (item in items) {
                                val line = when (item) {
                                    BrowserListItem.ParentDir -> "[上へ] .. (親フォルダへ戻る)"
                                    is BrowserListItem.Folder -> "[DIR]   ${item.entry.name}"
                                    is BrowserListItem.File -> "[${item.previewType.label.padEnd(5)}] ${item.entry.name}  (${SmbFormatUtils.formatBytes(item.entry.size)})"
                                }
                                addListItem(lb, line)
                            }
                            SendMessageW(lb, LB_SETHORIZONTALEXTENT.toUInt(), 900u, 0L)
                        }
                        setStatus("$displayPath を表示しました。")
                    },
                    onFailure = { e ->
                        setStatus("一覧取得エラー: ${e.message ?: e::class.simpleName}")
                        setPreviewText("ディレクトリ取得エラー:\r\n${e.stackTraceToString()}")
                    },
                )
            }
        }
    }

    private fun openSelectedEntry(forceExternalStream: Boolean) {
        val idx = hListEntries?.let { SendMessageW(it, LB_GETCURSEL.toUInt(), 0u, 0L).toInt() } ?: -1
        val item = currentListItems.getOrNull(idx) ?: return

        when (item) {
            BrowserListItem.ParentDir -> {
                val parent = SmbFormatUtils.parentPath(currentDirectoryPath) ?: ""
                loadDirectory(currentShareName, parent)
            }
            is BrowserListItem.Folder -> {
                val nextPath = SmbFormatUtils.joinPath(currentDirectoryPath, item.entry.name)
                loadDirectory(currentShareName, nextPath)
            }
            is BrowserListItem.File -> {
                val filePath = SmbFormatUtils.joinPath(currentDirectoryPath, item.entry.name)
                if (!forceExternalStream && item.previewType == SmbPreviewType.TEXT) {
                    previewTextFile(currentShareName, filePath, item.entry)
                } else {
                    startStreamingFile(currentShareName, filePath, item.entry)
                }
            }
        }
    }

    private fun previewTextFile(shareName: String, filePath: String, entry: SmbDirectoryEntry) {
        setStatus("テキストファイル ${entry.name} を読み込み中...")
        scope.launch {
            val result = runCatching {
                session.readTextFile(shareName = shareName, filePath = filePath)
            }
            postToUi {
                result.fold(
                    onSuccess = { content ->
                        val normalizedText = content.text.replace("\r\n", "\n").replace("\n", "\r\n")
                        val header = "=== ${content.fileName} (${SmbFormatUtils.formatBytes(content.totalSize)}) ===\r\n\r\n"
                        setPreviewText(header + normalizedText)
                        setStatus("${content.fileName} を表示しました (${SmbFormatUtils.formatBytes(content.loadedBytes.toLong())})。")
                    },
                    onFailure = { e ->
                        setStatus("テキスト読み込みエラー: ${e.message}")
                        setPreviewText("エラー:\r\n${e.stackTraceToString()}")
                    },
                )
            }
        }
    }

    private fun startStreamingFile(shareName: String, filePath: String, entry: SmbDirectoryEntry) {
        setStatus("${entry.name} の HTTP Range ストリーミングを開始中...")
        scope.launch {
            streamMonitorJob?.cancel()
            runCatching { activeHttpServer?.closeSuspend() }
            activeHttpServer = null

            val result = runCatching {
                val stream = session.openRandomAccessStream(
                    shareName = shareName,
                    filePath = filePath,
                    cacheWindowBytes = 256 * 1024,
                )
                SmbHttpRangeServer.start(stream = stream, fileName = entry.name)
            }

            postToUi {
                result.fold(
                    onSuccess = { server ->
                        activeHttpServer = server
                        val url = server.streamUrl
                        setStatus("ストリーミング配信中: $url")
                        setPreviewText(
                            buildString {
                                appendLine("=== SMB オンデマンド・ストリーミング配信中 ===")
                                appendLine("ファイル名 : ${entry.name}")
                                appendLine("サイズ     : ${SmbFormatUtils.formatBytes(entry.size)} (${entry.size} bytes)")
                                appendLine("配信 URL   : $url")
                                appendLine()
                                appendLine("全量ダウンロードを行わず、256KB ブロック LRU キャッシュ＋先読みによって")
                                appendLine("シーク位置に応じたオンデマンド SMB ストリーミングを行っています。")
                            },
                        )
                        launchExternalPlayer(url)
                        startStreamProgressMonitor(entry, server)
                    },
                    onFailure = { e ->
                        setStatus("ストリーミング開始エラー: ${e.message}")
                        setPreviewText("ストリーミング開始エラー:\r\n${e.stackTraceToString()}")
                    },
                )
            }
        }
    }

    private fun startStreamProgressMonitor(entry: SmbDirectoryEntry, server: SmbHttpRangeServer) {
        streamMonitorJob?.cancel()
        streamMonitorJob = scope.launch {
            while (isActive && activeHttpServer === server) {
                val fetched = server.stream.totalFetchedBytes
                val lastPos = server.stream.lastReadPosition
                postToUi {
                    if (activeHttpServer === server) {
                        setPreviewText(
                            buildString {
                                appendLine("=== SMB オンデマンド・ストリーミング配信中 ===")
                                appendLine("ファイル名   : ${entry.name}")
                                appendLine("ファイル容量 : ${SmbFormatUtils.formatBytes(entry.size)} (${entry.size} bytes)")
                                appendLine("配信 URL     : ${server.streamUrl}")
                                appendLine("取得済み通信 : ${SmbFormatUtils.formatBytes(fetched)}")
                                appendLine("現在読取位置 : ${SmbFormatUtils.formatBytes(lastPos)}")
                                appendLine()
                                appendLine("※ 外部プレイヤー (VLC / Windows メディアプレイヤー) で再生・シーク可能です。")
                            },
                        )
                    }
                }
                delay(500L)
            }
        }
    }

    private fun launchExternalPlayer(url: String) {
        val vlcPaths = listOf(
            "C:\\Program Files\\VideoLAN\\VLC\\vlc.exe",
            "C:\\Program Files (x86)\\VideoLAN\\VLC\\vlc.exe",
        )
        val vlcExe = vlcPaths.firstOrNull { GetFileAttributesW(it) != INVALID_FILE_ATTRIBUTES }
        if (vlcExe != null) {
            ShellExecuteW(mainHwnd, "open", vlcExe, "--avi-index=2 \"$url\"", null, SW_SHOWNORMAL)
        } else {
            ShellExecuteW(mainHwnd, "open", url, null, null, SW_SHOWNORMAL)
        }
    }

    fun onDestroy() {
        streamMonitorJob?.cancel()
        runBlocking {
            runCatching { activeHttpServer?.closeSuspend() }
            runCatching { session.closeSuspend() }
        }
        uiFont?.let { DeleteObject(it) }
        monoFont?.let { DeleteObject(it) }
        PostQuitMessage(0)
    }

    private fun setStatus(text: String) {
        hStaticStatus?.let { SetWindowTextW(it, text) }
    }

    private fun setPreviewText(text: String) {
        hEditPreview?.let { SetWindowTextW(it, text) }
    }

    private fun createLabel(parent: HWND, hInst: HINSTANCE?, text: String, x: Int, y: Int, w: Int, h: Int): HWND? {
        return CreateWindowExW(
            0u, "STATIC", text,
            (WS_CHILD or WS_VISIBLE).toUInt(),
            x, y, w, h,
            parent, null, hInst, null,
        )?.also { applyFont(it, uiFont) }
    }

    private fun createEdit(
        parent: HWND,
        hInst: HINSTANCE?,
        id: Int,
        initial: String,
        x: Int,
        y: Int,
        w: Int,
        h: Int,
        isPassword: Boolean = false,
    ): HWND? {
        var style = WS_CHILD or WS_VISIBLE or WS_TABSTOP or ES_AUTOHSCROLL
        if (isPassword) style = style or ES_PASSWORD
        return CreateWindowExW(
            WS_EX_CLIENTEDGE.toUInt(), "EDIT", initial,
            style.toUInt(),
            x, y, w, h,
            parent, id.toLong().toCPointer(), hInst, null,
        )?.also { applyFont(it, uiFont) }
    }

    private fun createButton(parent: HWND, hInst: HINSTANCE?, id: Int, text: String, x: Int, y: Int, w: Int, h: Int): HWND? {
        return CreateWindowExW(
            0u, "BUTTON", text,
            (WS_CHILD or WS_VISIBLE or WS_TABSTOP or BS_PUSHBUTTON).toUInt(),
            x, y, w, h,
            parent, id.toLong().toCPointer(), hInst, null,
        )?.also { applyFont(it, uiFont) }
    }

    private fun applyFont(hwnd: HWND, font: HFONT?) {
        if (font != null) {
            SendMessageW(hwnd, WM_SETFONT.toUInt(), font.rawValue.toLong().toULong(), 1L)
        }
    }

    private fun addComboItem(combo: HWND, text: String) = memScoped {
        SendMessageW(combo, CB_ADDSTRING.toUInt(), 0u, text.wcstr.ptr.rawValue.toLong())
    }

    private fun addListItem(listBox: HWND, text: String) = memScoped {
        SendMessageW(listBox, LB_ADDSTRING.toUInt(), 0u, text.wcstr.ptr.rawValue.toLong())
    }

    private fun getControlText(hwnd: HWND?): String = memScoped {
        if (hwnd == null) return ""
        val len = GetWindowTextLengthW(hwnd)
        if (len <= 0) return ""
        val buf = allocArray<WCHARVar>(len + 1)
        GetWindowTextW(hwnd, buf, len + 1)
        buf.toKStringFromUtf16()
    }
}

@Suppress("UNUSED_PARAMETER")
private fun windowProc(hwnd: HWND?, uMsg: UINT, wParam: WPARAM, lParam: LPARAM): LRESULT {
    if (hwnd == null) return 0L
    return when (uMsg.toInt()) {
        WM_CREATE -> {
            WindowsSmbGuiApp.onCreate(hwnd)
            0L
        }
        WM_COMMAND -> {
            val id = (wParam.toInt() and 0xFFFF)
            val code = ((wParam.toInt() ushr 16) and 0xFFFF)
            WindowsSmbGuiApp.onCommand(id, code)
            0L
        }
        WM_APP_RUN_UI.toInt() -> {
            WindowsSmbGuiApp.drainUiTasks()
            0L
        }
        WM_DESTROY -> {
            WindowsSmbGuiApp.onDestroy()
            0L
        }
        else -> DefWindowProcW(hwnd, uMsg, wParam, lParam)
    }
}
