package com.sorrowblue.kmcifs.sample.ios

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.detectTransformGestures
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clipToBounds
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.graphics.toComposeImageBitmap
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.interop.UIKitView
import androidx.compose.ui.window.ComposeUIViewController
import com.sorrowblue.kmcifs.client.protocol.SmbDirectoryEntry
import com.sorrowblue.kmcifs.client.protocol.SmbShareInfo
import com.sorrowblue.kmcifs.sample.SmbBrowserSession
import com.sorrowblue.kmcifs.sample.SmbConnectionSummary
import com.sorrowblue.kmcifs.sample.SmbCredentialCipher
import com.sorrowblue.kmcifs.sample.SmbDirectoryListing
import com.sorrowblue.kmcifs.sample.SmbFormatUtils
import com.sorrowblue.kmcifs.sample.SmbHttpRangeServer
import com.sorrowblue.kmcifs.sample.SmbPreviewType
import com.sorrowblue.kmcifs.sample.SmbRandomAccessStream
import com.sorrowblue.kmcifs.sample.SmbSavedConnection
import com.sorrowblue.kmcifs.sample.SmbTextFileContent
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.random.Random
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.jetbrains.skia.Image as SkiaImage
import platform.AVFoundation.AVPlayer
import platform.AVFoundation.AVPlayerLayer
import platform.AVFoundation.pause
import platform.AVFoundation.play
import platform.Foundation.NSURL
import platform.Foundation.NSUserDefaults
import platform.UIKit.UIView
import platform.UIKit.UIViewController

fun MainViewController(): UIViewController = ComposeUIViewController {
    MaterialTheme {
        SmbIosSampleScreen()
    }
}

/**
 * Persists encrypted SMB connection settings on iOS using AES-128-GCM.
 */
private object IosEncryptedConnectionStore {
    private const val KEY_DEVICE_SECRET = "kmcifs.ios.sample.secret_key"
    private const val KEY_ENCRYPTED_PAYLOAD = "kmcifs.ios.sample.encrypted_connection"

    private val defaults: NSUserDefaults
        get() = NSUserDefaults.standardUserDefaults

    fun save(connection: SmbSavedConnection) {
        val key = getOrCreateKey()
        val encrypted = SmbCredentialCipher.encryptToBase64(connection, key)
        defaults.setObject(encrypted, forKey = KEY_ENCRYPTED_PAYLOAD)
        defaults.synchronize()
    }

    fun load(): SmbSavedConnection? {
        val encrypted = defaults.stringForKey(KEY_ENCRYPTED_PAYLOAD) ?: return null
        return runCatching {
            val key = getOrCreateKey()
            SmbCredentialCipher.decryptFromBase64(encrypted, key)
        }.onFailure {
            clear()
        }.getOrNull()
    }

    fun clear() {
        defaults.removeObjectForKey(KEY_ENCRYPTED_PAYLOAD)
        defaults.synchronize()
    }

    @OptIn(ExperimentalEncodingApi::class)
    private fun getOrCreateKey(): ByteArray {
        val existing = defaults.stringForKey(KEY_DEVICE_SECRET)
        if (existing != null) {
            val decoded = runCatching { Base64.decode(existing) }.getOrNull()
            if (decoded != null && decoded.size == 16) {
                return decoded
            }
        }
        val newKey = Random.Default.nextBytes(16)
        defaults.setObject(Base64.encode(newKey), forKey = KEY_DEVICE_SECRET)
        defaults.synchronize()
        return newKey
    }
}

@Composable
fun SmbIosSampleScreen() {
    val scope = rememberCoroutineScope()
    val browserSession = remember { SmbBrowserSession() }

    val initialSaved = remember { IosEncryptedConnectionStore.load() }
    var hasStoredCredentials by remember { mutableStateOf(initialSaved != null) }

    var host by remember { mutableStateOf(initialSaved?.host ?: "192.168.1.100") }
    var portText by remember { mutableStateOf((initialSaved?.port ?: 445).toString()) }
    var username by remember { mutableStateOf(initialSaved?.username ?: "") }
    var password by remember { mutableStateOf(initialSaved?.password ?: "") }
    var domain by remember { mutableStateOf(initialSaved?.domain ?: "") }
    var shareName by remember { mutableStateOf(initialSaved?.shareName ?: "") }
    var directoryPath by remember { mutableStateOf(initialSaved?.directoryPath ?: "") }
    var saveCredentials by remember { mutableStateOf(true) }

    var loading by remember { mutableStateOf(false) }
    var errorMessage by remember { mutableStateOf<String?>(null) }

    var connectionSummary by remember { mutableStateOf<SmbConnectionSummary?>(null) }
    var shareList by remember { mutableStateOf<List<SmbShareInfo>>(emptyList()) }
    var currentListing by remember { mutableStateOf<SmbDirectoryListing?>(null) }
    var selectedFile by remember { mutableStateOf<SmbDirectoryEntry?>(null) }

    DisposableEffect(browserSession) {
        onDispose {
            scope.launch(Dispatchers.IO + NonCancellable) {
                browserSession.closeSuspend()
            }
        }
    }

    fun buildCurrentConfig(): SmbSavedConnection {
        return SmbSavedConnection(
            host = host.trim(),
            port = portText.trim().toIntOrNull()?.coerceIn(1, 65535) ?: 445,
            username = username.trim(),
            password = password,
            domain = domain.trim(),
            shareName = shareName.trim(),
            directoryPath = directoryPath.trim(),
        )
    }

    fun persistIfEnabled(config: SmbSavedConnection) {
        if (saveCredentials) {
            runCatching {
                IosEncryptedConnectionStore.save(config)
                hasStoredCredentials = true
            }
        }
    }

    fun navigateToDirectory(targetShare: String, targetPath: String) {
        val cleanShare = targetShare.trim('/', '\\', ' ')
        val cleanPath = SmbFormatUtils.normalizePath(targetPath)
        loading = true
        errorMessage = null
        scope.launch {
            val result = runCatching {
                withContext(Dispatchers.IO) {
                    browserSession.listDirectory(cleanShare, cleanPath)
                }
            }
            result.fold(
                onSuccess = { listing ->
                    currentListing = listing
                    selectedFile = null
                    shareName = cleanShare
                    directoryPath = cleanPath
                    persistIfEnabled(buildCurrentConfig())
                },
                onFailure = { e ->
                    errorMessage = e.message ?: e::class.simpleName ?: "フォルダ一覧の取得に失敗しました"
                },
            )
            loading = false
        }
    }

    fun disconnectSession() {
        loading = true
        scope.launch {
            withContext(Dispatchers.IO) {
                browserSession.closeSuspend()
            }
            connectionSummary = null
            currentListing = null
            selectedFile = null
            shareList = emptyList()
            errorMessage = null
            loading = false
        }
    }

    Scaffold(modifier = Modifier.fillMaxSize()) { innerPadding ->
        Box(
            modifier = Modifier
                .padding(innerPadding)
                .fillMaxSize(),
        ) {
            val activeSummary = connectionSummary
            val activeListing = currentListing
            val activeFile = selectedFile

            when {
                activeSummary == null -> {
                    var showPassword by remember { mutableStateOf(false) }
                    Column(
                        modifier = Modifier
                            .fillMaxSize()
                            .verticalScroll(rememberScrollState())
                            .padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(10.dp),
                    ) {
                        Text(
                            text = "kmcifs iOS Sample",
                            style = MaterialTheme.typography.headlineSmall,
                            fontWeight = FontWeight.Bold,
                        )

                        if (hasStoredCredentials) {
                            Surface(
                                color = MaterialTheme.colorScheme.secondaryContainer,
                                shape = RoundedCornerShape(8.dp),
                                modifier = Modifier.fillMaxWidth(),
                            ) {
                                Row(
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
                                ) {
                                    Text(
                                        text = "暗号化保存済みの接続情報を復元しました",
                                        style = MaterialTheme.typography.bodySmall,
                                        modifier = Modifier.weight(1f),
                                    )
                                    TextButton(
                                        onClick = {
                                            IosEncryptedConnectionStore.clear()
                                            hasStoredCredentials = false
                                        },
                                    ) {
                                        Text("保存削除")
                                    }
                                }
                            }
                        }

                        Row(
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                            modifier = Modifier.fillMaxWidth(),
                        ) {
                            OutlinedTextField(
                                value = host,
                                onValueChange = { host = it },
                                label = { Text("Host / IP") },
                                singleLine = true,
                                modifier = Modifier.weight(0.7f),
                            )
                            OutlinedTextField(
                                value = portText,
                                onValueChange = { portText = it },
                                label = { Text("Port") },
                                singleLine = true,
                                modifier = Modifier.weight(0.3f),
                            )
                        }

                        OutlinedTextField(
                            value = username,
                            onValueChange = { username = it },
                            label = { Text("Username") },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth(),
                        )

                        OutlinedTextField(
                            value = password,
                            onValueChange = { password = it },
                            label = { Text("Password") },
                            singleLine = true,
                            visualTransformation = if (showPassword) VisualTransformation.None else PasswordVisualTransformation(),
                            trailingIcon = {
                                TextButton(onClick = { showPassword = !showPassword }) {
                                    Text(if (showPassword) "隠す" else "表示")
                                }
                            },
                            modifier = Modifier.fillMaxWidth(),
                        )

                        OutlinedTextField(
                            value = domain,
                            onValueChange = { domain = it },
                            label = { Text("Domain (任意)") },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth(),
                        )

                        OutlinedTextField(
                            value = shareName,
                            onValueChange = { shareName = it },
                            label = { Text("Share Name (空欄時は共有フォルダ一覧を表示)") },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth(),
                        )

                        OutlinedTextField(
                            value = directoryPath,
                            onValueChange = { directoryPath = it },
                            label = { Text("初期フォルダパス (任意)") },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth(),
                        )

                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable { saveCredentials = !saveCredentials },
                        ) {
                            Checkbox(
                                checked = saveCredentials,
                                onCheckedChange = { saveCredentials = it },
                            )
                            Text("接続情報を暗号化して端末に保存する")
                        }

                        if (errorMessage != null) {
                            Text(
                                text = errorMessage!!,
                                color = MaterialTheme.colorScheme.error,
                                style = MaterialTheme.typography.bodySmall,
                            )
                        }

                        Button(
                            enabled = !loading && host.isNotBlank(),
                            onClick = {
                                val config = buildCurrentConfig()
                                persistIfEnabled(config)
                                loading = true
                                errorMessage = null
                                scope.launch {
                                    val result = runCatching {
                                        withContext(Dispatchers.IO) {
                                            val summary = browserSession.connect(config)
                                            val shares = runCatching {
                                                browserSession.listShares(includeHidden = false)
                                            }.getOrElse { emptyList() }
                                            val initialListing = if (config.shareName.isNotBlank()) {
                                                browserSession.listDirectory(config.shareName, config.directoryPath)
                                            } else {
                                                null
                                            }
                                            Triple(summary, shares, initialListing)
                                        }
                                    }
                                    result.fold(
                                        onSuccess = { (summary, shares, initialListing) ->
                                            connectionSummary = summary
                                            shareList = shares
                                            currentListing = initialListing
                                            selectedFile = null
                                        },
                                        onFailure = { e ->
                                            errorMessage = "接続エラー: ${e.message ?: e::class.simpleName}"
                                        },
                                    )
                                    loading = false
                                }
                            },
                            modifier = Modifier.fillMaxWidth(),
                        ) {
                            Text(if (loading) "接続中..." else "SMB サーバーへ接続")
                        }
                    }
                }

                activeFile != null && activeListing != null -> {
                    val fileFullPath = SmbFormatUtils.joinPath(activeListing.directoryPath, activeFile.name)
                    IosFileViewerScreen(
                        session = browserSession,
                        shareName = activeListing.shareName,
                        filePath = fileFullPath,
                        entry = activeFile,
                        onBack = { selectedFile = null },
                    )
                }

                activeListing != null -> {
                    Column(modifier = Modifier.fillMaxSize()) {
                        Surface(tonalElevation = 2.dp, modifier = Modifier.fillMaxWidth()) {
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.SpaceBetween,
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(horizontal = 16.dp, vertical = 10.dp),
                            ) {
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(
                                        text = "//${activeListing.connection.host}/${activeListing.shareName}/${activeListing.directoryPath}",
                                        style = MaterialTheme.typography.titleMedium,
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis,
                                    )
                                    Text(
                                        text = "${activeListing.connection.negotiatedDialect}",
                                        style = MaterialTheme.typography.labelSmall,
                                    )
                                }
                                OutlinedButton(onClick = { disconnectSession() }) {
                                    Text("切断")
                                }
                            }
                        }

                        Row(
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(horizontal = 16.dp, vertical = 8.dp),
                        ) {
                            OutlinedButton(
                                enabled = !loading,
                                onClick = {
                                    val parent = SmbFormatUtils.parentPath(activeListing.directoryPath)
                                    if (parent != null) {
                                        navigateToDirectory(activeListing.shareName, parent)
                                    } else {
                                        currentListing = null
                                    }
                                },
                            ) {
                                Text(if (activeListing.directoryPath.isEmpty()) "← 共有一覧へ" else "↑ 上の階層へ")
                            }
                            Spacer(modifier = Modifier.weight(1f))
                            FilledTonalButton(
                                enabled = !loading,
                                onClick = { navigateToDirectory(activeListing.shareName, activeListing.directoryPath) },
                            ) {
                                Text("更新")
                            }
                        }

                        HorizontalDivider()

                        if (errorMessage != null) {
                            Text(
                                text = errorMessage!!,
                                color = MaterialTheme.colorScheme.error,
                                style = MaterialTheme.typography.bodySmall,
                                modifier = Modifier.padding(16.dp),
                            )
                        }

                        LazyColumn(
                            contentPadding = PaddingValues(16.dp),
                            verticalArrangement = Arrangement.spacedBy(6.dp),
                            modifier = Modifier.fillMaxSize(),
                        ) {
                            item {
                                Text(
                                    text = "フォルダ一覧 (${activeListing.folders.size} 件)",
                                    style = MaterialTheme.typography.titleSmall,
                                    fontWeight = FontWeight.Bold,
                                    color = MaterialTheme.colorScheme.primary,
                                )
                            }
                            items(activeListing.folders, key = { "dir_${it.name}" }) { folder ->
                                Card(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .clickable(enabled = !loading) {
                                            val next = SmbFormatUtils.joinPath(activeListing.directoryPath, folder.name)
                                            navigateToDirectory(activeListing.shareName, next)
                                        },
                                ) {
                                    Row(
                                        verticalAlignment = Alignment.CenterVertically,
                                        horizontalArrangement = Arrangement.SpaceBetween,
                                        modifier = Modifier.padding(14.dp),
                                    ) {
                                        Text("[DIR] ${folder.name}", fontWeight = FontWeight.Medium)
                                        Text("→")
                                    }
                                }
                            }

                            item {
                                Spacer(modifier = Modifier.height(8.dp))
                                Text(
                                    text = "ファイル一覧 (${activeListing.files.size} 件)",
                                    style = MaterialTheme.typography.titleSmall,
                                    fontWeight = FontWeight.Bold,
                                    color = MaterialTheme.colorScheme.primary,
                                )
                            }
                            items(activeListing.files, key = { "file_${it.name}" }) { file ->
                                val pType = SmbPreviewType.fromFileName(file.name)
                                Card(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .clickable(enabled = !loading) { selectedFile = file },
                                ) {
                                    Row(
                                        verticalAlignment = Alignment.CenterVertically,
                                        horizontalArrangement = Arrangement.SpaceBetween,
                                        modifier = Modifier.padding(14.dp),
                                    ) {
                                        Column(modifier = Modifier.weight(1f)) {
                                            Text("[${pType.label}] ${file.name}")
                                            Text(
                                                text = SmbFormatUtils.formatBytes(file.size),
                                                style = MaterialTheme.typography.bodySmall,
                                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                            )
                                        }
                                        Text("表示", color = MaterialTheme.colorScheme.primary)
                                    }
                                }
                            }
                        }
                    }
                }

                else -> {
                    Column(modifier = Modifier.fillMaxSize()) {
                        Surface(tonalElevation = 2.dp, modifier = Modifier.fillMaxWidth()) {
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.SpaceBetween,
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(horizontal = 16.dp, vertical = 10.dp),
                            ) {
                                Text(
                                    text = "//${activeSummary.host} (共有フォルダ一覧)",
                                    style = MaterialTheme.typography.titleMedium,
                                )
                                OutlinedButton(onClick = { disconnectSession() }) {
                                    Text("切断")
                                }
                            }
                        }
                        HorizontalDivider()

                        LazyColumn(
                            contentPadding = PaddingValues(16.dp),
                            verticalArrangement = Arrangement.spacedBy(8.dp),
                            modifier = Modifier.fillMaxSize(),
                        ) {
                            item {
                                Card(
                                    colors = CardDefaults.cardColors(
                                        containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f),
                                    ),
                                    modifier = Modifier.fillMaxWidth(),
                                ) {
                                    Row(
                                        verticalAlignment = Alignment.CenterVertically,
                                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                                        modifier = Modifier.padding(12.dp),
                                    ) {
                                        OutlinedTextField(
                                            value = shareName,
                                            onValueChange = { shareName = it },
                                            label = { Text("Share Name を直接指定") },
                                            singleLine = true,
                                            modifier = Modifier.weight(1f),
                                        )
                                        Button(
                                            enabled = !loading && shareName.isNotBlank(),
                                            onClick = { navigateToDirectory(shareName.trim(), "") },
                                        ) {
                                            Text("開く")
                                        }
                                    }
                                }
                            }

                            items(shareList, key = { it.name }) { share ->
                                Card(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .clickable(enabled = !loading) { navigateToDirectory(share.name, "") },
                                ) {
                                    Row(
                                        verticalAlignment = Alignment.CenterVertically,
                                        horizontalArrangement = Arrangement.SpaceBetween,
                                        modifier = Modifier.padding(14.dp),
                                    ) {
                                        Column(modifier = Modifier.weight(1f)) {
                                            Text(share.name, fontWeight = FontWeight.Medium)
                                            if (share.comment.isNotBlank()) {
                                                Text(share.comment, style = MaterialTheme.typography.bodySmall)
                                            }
                                        }
                                        Text("開く →", color = MaterialTheme.colorScheme.primary)
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

@OptIn(ExperimentalForeignApi::class)
@Composable
private fun IosFileViewerScreen(
    session: SmbBrowserSession,
    shareName: String,
    filePath: String,
    entry: SmbDirectoryEntry,
    onBack: () -> Unit,
) {
    var activeType by remember(shareName, filePath) { mutableStateOf(SmbPreviewType.fromFileName(entry.name)) }

    Column(modifier = Modifier.fillMaxSize()) {
        Surface(tonalElevation = 2.dp, modifier = Modifier.fillMaxWidth()) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(12.dp),
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 10.dp),
            ) {
                OutlinedButton(onClick = onBack) {
                    Text("← 一覧へ戻る")
                }
                Column(modifier = Modifier.weight(1f)) {
                    Text(entry.name, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    Text(
                        text = SmbFormatUtils.formatBytes(entry.size),
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
            }
        }
        HorizontalDivider()

        Box(modifier = Modifier.fillMaxSize().weight(1f)) {
            when (activeType) {
                SmbPreviewType.TEXT -> {
                    var loading by remember(shareName, filePath) { mutableStateOf(true) }
                    var content by remember(shareName, filePath) { mutableStateOf<SmbTextFileContent?>(null) }
                    var error by remember(shareName, filePath) { mutableStateOf<String?>(null) }

                    LaunchedEffect(shareName, filePath) {
                        loading = true
                        error = null
                        runCatching {
                            withContext(Dispatchers.IO) { session.readTextFile(shareName, filePath) }
                        }.fold(
                            onSuccess = { content = it },
                            onFailure = { error = it.message },
                        )
                        loading = false
                    }

                    when {
                        loading -> Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) { CircularProgressIndicator() }
                        error != null -> Text("エラー: $error", modifier = Modifier.padding(16.dp))
                        content != null -> SelectionContainer(modifier = Modifier.fillMaxSize()) {
                            Text(
                                text = content!!.text,
                                fontFamily = FontFamily.Monospace,
                                modifier = Modifier
                                    .fillMaxSize()
                                    .verticalScroll(rememberScrollState())
                                    .horizontalScroll(rememberScrollState())
                                    .padding(16.dp),
                            )
                        }
                    }
                }

                SmbPreviewType.IMAGE -> {
                    var loading by remember(shareName, filePath) { mutableStateOf(true) }
                    var bitmap by remember(shareName, filePath) { mutableStateOf<ImageBitmap?>(null) }
                    var error by remember(shareName, filePath) { mutableStateOf<String?>(null) }
                    var scale by remember(shareName, filePath) { mutableFloatStateOf(1f) }
                    var offset by remember(shareName, filePath) { mutableStateOf(Offset.Zero) }

                    LaunchedEffect(shareName, filePath) {
                        loading = true
                        error = null
                        runCatching {
                            withContext(Dispatchers.IO) {
                                val bytes = session.readFileBytes(shareName, filePath)
                                SkiaImage.makeFromEncoded(bytes).toComposeImageBitmap()
                            }
                        }.fold(
                            onSuccess = { bitmap = it },
                            onFailure = { error = it.message },
                        )
                        loading = false
                    }

                    when {
                        loading -> Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) { CircularProgressIndicator() }
                        error != null -> Text("エラー: $error", modifier = Modifier.padding(16.dp))
                        bitmap != null -> Box(
                            contentAlignment = Alignment.Center,
                            modifier = Modifier
                                .fillMaxSize()
                                .background(Color.Black)
                                .clipToBounds()
                                .pointerInput(shareName, filePath) {
                                    detectTransformGestures { _, pan, zoom, _ ->
                                        scale = (scale * zoom).coerceIn(1f, 5f)
                                        offset = if (scale > 1f) offset + pan else Offset.Zero
                                    }
                                },
                        ) {
                            Image(
                                bitmap = bitmap!!,
                                contentDescription = entry.name,
                                contentScale = ContentScale.Fit,
                                modifier = Modifier
                                    .fillMaxSize()
                                    .graphicsLayer(
                                        scaleX = scale,
                                        scaleY = scale,
                                        translationX = offset.x,
                                        translationY = offset.y,
                                    ),
                            )
                        }
                    }
                }

                SmbPreviewType.VIDEO -> {
                    val videoScope = rememberCoroutineScope()
                    var loading by remember(shareName, filePath) { mutableStateOf(true) }
                    var httpServer by remember(shareName, filePath) { mutableStateOf<SmbHttpRangeServer?>(null) }
                    var error by remember(shareName, filePath) { mutableStateOf<String?>(null) }
                    var playerRef by remember(shareName, filePath) { mutableStateOf<AVPlayer?>(null) }

                    DisposableEffect(shareName, filePath) {
                        onDispose {
                            playerRef?.pause()
                            playerRef = null
                            val serverToClose = httpServer
                            httpServer = null
                            serverToClose?.markClosed()
                            if (serverToClose != null) {
                                videoScope.launch(Dispatchers.IO + NonCancellable) {
                                    runCatching { serverToClose.closeSuspend() }
                                }
                            }
                        }
                    }

                    LaunchedEffect(shareName, filePath) {
                        loading = true
                        error = null
                        var openedStream: SmbRandomAccessStream? = null
                        var openedServer: SmbHttpRangeServer? = null
                        runCatching {
                            withContext(Dispatchers.IO) {
                                val stream = session.openRandomAccessStream(
                                    shareName = shareName,
                                    filePath = filePath,
                                    cacheWindowBytes = 256 * 1024,
                                )
                                openedStream = stream
                                val server = SmbHttpRangeServer.start(
                                    stream = stream,
                                    fileName = entry.name,
                                )
                                openedServer = server
                                server
                            }
                        }.fold(
                            onSuccess = { server ->
                                httpServer = server
                            },
                            onFailure = { e ->
                                openedStream?.markClosed()
                                openedServer?.markClosed()
                                withContext(Dispatchers.IO + NonCancellable) {
                                    runCatching { openedServer?.closeSuspend() }
                                    runCatching { openedStream?.closeSuspend() }
                                }
                                error = e.message ?: e::class.simpleName ?: "動画ストリームを開けませんでした"
                            },
                        )
                        loading = false
                    }

                    when {
                        loading -> Box(Modifier.fillMaxSize().padding(24.dp), contentAlignment = Alignment.Center) {
                            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                                CircularProgressIndicator()
                                Spacer(Modifier.height(8.dp))
                                Text("SMB ストリーミング接続を開始中...")
                            }
                        }
                        error != null -> Text("エラー: $error", modifier = Modifier.padding(16.dp))
                        httpServer != null -> {
                            val server = httpServer!!
                            Column(modifier = Modifier.fillMaxSize()) {
                                UIKitView(
                                    factory = {
                                        val view = UIView()
                                        val url = NSURL.URLWithString(server.streamUrl)!!
                                        val player = AVPlayer.playerWithURL(url)
                                        playerRef = player
                                        val layer = AVPlayerLayer.playerLayerWithPlayer(player)
                                        view.layer.addSublayer(layer)
                                        player.play()
                                        view
                                    },
                                    update = { view ->
                                        (view.layer.sublayers?.firstOrNull() as? AVPlayerLayer)?.frame = view.bounds
                                    },
                                    modifier = Modifier.fillMaxWidth().weight(1f),
                                )
                                Row(
                                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                                    modifier = Modifier.fillMaxWidth().padding(16.dp),
                                ) {
                                    Button(onClick = { playerRef?.play() }) { Text("再生") }
                                    OutlinedButton(onClick = { playerRef?.pause() }) { Text("一時停止") }
                                }
                            }
                        }
                    }
                }

                SmbPreviewType.OTHER -> {
                    Column(
                        verticalArrangement = Arrangement.spacedBy(10.dp),
                        modifier = Modifier.padding(24.dp),
                    ) {
                        Text("「${entry.name}」を開く形式を選択してください")
                        Button(onClick = { activeType = SmbPreviewType.TEXT }, modifier = Modifier.fillMaxWidth()) {
                            Text("テキストとして表示")
                        }
                        FilledTonalButton(onClick = { activeType = SmbPreviewType.IMAGE }, modifier = Modifier.fillMaxWidth()) {
                            Text("画像として表示")
                        }
                        FilledTonalButton(onClick = { activeType = SmbPreviewType.VIDEO }, modifier = Modifier.fillMaxWidth()) {
                            Text("動画として再生")
                        }
                    }
                }
            }
        }
    }
}
