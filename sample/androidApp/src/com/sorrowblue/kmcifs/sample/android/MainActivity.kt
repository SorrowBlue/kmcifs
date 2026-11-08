package com.sorrowblue.kmcifs.sample.android

import android.content.Context
import android.content.pm.PackageManager
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
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
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.sorrowblue.kmcifs.client.protocol.SmbDirectoryEntry
import com.sorrowblue.kmcifs.client.protocol.SmbShareInfo
import com.sorrowblue.kmcifs.sample.SmbBrowserSession
import com.sorrowblue.kmcifs.sample.SmbConnectionSummary
import com.sorrowblue.kmcifs.sample.SmbDirectoryListing
import com.sorrowblue.kmcifs.sample.SmbFormatUtils
import com.sorrowblue.kmcifs.sample.SmbPreviewType
import com.sorrowblue.kmcifs.sample.SmbSavedConnection
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                SmbAndroidSampleApp()
            }
        }
    }
}

private val LOCAL_NETWORK_PERMISSIONS = listOf(
    "android.permission.ACCESS_LOCAL_NETWORK",
    "android.permission.NEARBY_WIFI_DEVICES",
)

private fun Context.findMissingLocalNetworkPermissions(): Array<String> {
    val pm = packageManager
    return LOCAL_NETWORK_PERMISSIONS.filter { perm ->
        val existsOnDevice = runCatching { pm.getPermissionInfo(perm, 0) }.isSuccess
        existsOnDevice && checkSelfPermission(perm) != PackageManager.PERMISSION_GRANTED
    }.toTypedArray()
}

@Composable
fun SmbAndroidSampleApp() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val connectionStore = remember(context) { EncryptedConnectionStore(context) }
    val browserSession = remember { SmbBrowserSession() }

    var pendingConnectAfterPermission by remember { mutableStateOf<(() -> Unit)?>(null) }
    val permissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestMultiplePermissions(),
    ) {
        val action = pendingConnectAfterPermission
        pendingConnectAfterPermission = null
        action?.invoke()
    }

    LaunchedEffect(Unit) {
        val missing = context.findMissingLocalNetworkPermissions()
        if (missing.isNotEmpty()) {
            permissionLauncher.launch(missing)
        }
    }

    val initialSaved = remember(connectionStore) { connectionStore.load() }
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
                connectionStore.save(config)
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

    fun loadShareRootList() {
        loading = true
        errorMessage = null
        scope.launch {
            val result = runCatching {
                withContext(Dispatchers.IO) {
                    browserSession.listShares(includeHidden = false)
                }
            }
            result.fold(
                onSuccess = { shares ->
                    shareList = shares
                    currentListing = null
                    selectedFile = null
                },
                onFailure = { e ->
                    shareList = emptyList()
                    currentListing = null
                    selectedFile = null
                    errorMessage = "共有フォルダ一覧の自動取得に失敗しました (${e.message})。共有フォルダ名を直接入力して開いてください。"
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

    // システムの「戻る」ボタン操作のハンドリング
    BackHandler(enabled = connectionSummary != null) {
        when {
            selectedFile != null -> {
                selectedFile = null
            }
            currentListing != null -> {
                val listing = currentListing!!
                val parent = SmbFormatUtils.parentPath(listing.directoryPath)
                if (parent != null) {
                    navigateToDirectory(listing.shareName, parent)
                } else {
                    currentListing = null
                    if (shareList.isEmpty()) {
                        loadShareRootList()
                    }
                }
            }
            else -> {
                disconnectSession()
            }
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
                    ConnectionSetupScreen(
                        host = host,
                        onHostChange = { host = it },
                        portText = portText,
                        onPortTextChange = { portText = it },
                        username = username,
                        onUsernameChange = { username = it },
                        password = password,
                        onPasswordChange = { password = it },
                        domain = domain,
                        onDomainChange = { domain = it },
                        shareName = shareName,
                        onShareNameChange = { shareName = it },
                        directoryPath = directoryPath,
                        onDirectoryPathChange = { directoryPath = it },
                        saveCredentials = saveCredentials,
                        onSaveCredentialsChange = { saveCredentials = it },
                        hasStoredCredentials = hasStoredCredentials,
                        onClearStoredCredentials = {
                            connectionStore.clear()
                            hasStoredCredentials = false
                        },
                        loading = loading,
                        errorMessage = errorMessage,
                        onConnectClick = {
                            val startConnect = {
                                val config = buildCurrentConfig()
                                persistIfEnabled(config)
                                loading = true
                                errorMessage = null
                                scope.launch {
                                    val connectResult = runCatching {
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
                                    connectResult.fold(
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
                            }
                            val missingPerms = context.findMissingLocalNetworkPermissions()
                            if (missingPerms.isNotEmpty()) {
                                pendingConnectAfterPermission = { startConnect() }
                                permissionLauncher.launch(missingPerms)
                            } else {
                                startConnect()
                            }
                        },
                    )
                }

                activeFile != null && activeListing != null -> {
                    val fileFullPath = SmbFormatUtils.joinPath(activeListing.directoryPath, activeFile.name)
                    FileViewerScreen(
                        session = browserSession,
                        shareName = activeListing.shareName,
                        filePath = fileFullPath,
                        entry = activeFile,
                        onBack = { selectedFile = null },
                    )
                }

                activeListing != null -> {
                    DirectoryBrowserScreen(
                        listing = activeListing,
                        loading = loading,
                        errorMessage = errorMessage,
                        onNavigateUp = {
                            val parent = SmbFormatUtils.parentPath(activeListing.directoryPath)
                            if (parent != null) {
                                navigateToDirectory(activeListing.shareName, parent)
                            } else {
                                currentListing = null
                                if (shareList.isEmpty()) {
                                    loadShareRootList()
                                }
                            }
                        },
                        onRefresh = {
                            navigateToDirectory(activeListing.shareName, activeListing.directoryPath)
                        },
                        onDisconnect = { disconnectSession() },
                        onFolderClick = { folder ->
                            val nextPath = SmbFormatUtils.joinPath(activeListing.directoryPath, folder.name)
                            navigateToDirectory(activeListing.shareName, nextPath)
                        },
                        onFileClick = { file ->
                            selectedFile = file
                        },
                    )
                }

                else -> {
                    ShareListBrowserScreen(
                        summary = activeSummary,
                        shares = shareList,
                        manualShareInput = shareName,
                        onManualShareInputChange = { shareName = it },
                        loading = loading,
                        errorMessage = errorMessage,
                        onShareSelected = { selectedShare ->
                            navigateToDirectory(selectedShare, "")
                        },
                        onRefreshShares = { loadShareRootList() },
                        onDisconnect = { disconnectSession() },
                    )
                }
            }
        }
    }
}

@Composable
private fun ConnectionSetupScreen(
    host: String,
    onHostChange: (String) -> Unit,
    portText: String,
    onPortTextChange: (String) -> Unit,
    username: String,
    onUsernameChange: (String) -> Unit,
    password: String,
    onPasswordChange: (String) -> Unit,
    domain: String,
    onDomainChange: (String) -> Unit,
    shareName: String,
    onShareNameChange: (String) -> Unit,
    directoryPath: String,
    onDirectoryPathChange: (String) -> Unit,
    saveCredentials: Boolean,
    onSaveCredentialsChange: (Boolean) -> Unit,
    hasStoredCredentials: Boolean,
    onClearStoredCredentials: () -> Unit,
    loading: Boolean,
    errorMessage: String?,
    onConnectClick: () -> Unit,
) {
    var showPassword by remember { mutableStateOf(false) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Text(
            text = "kmcifs SMB クライアント",
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
                        color = MaterialTheme.colorScheme.onSecondaryContainer,
                        modifier = Modifier.weight(1f),
                    )
                    TextButton(onClick = onClearStoredCredentials) {
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
                onValueChange = onHostChange,
                label = { Text("Host / IP") },
                singleLine = true,
                modifier = Modifier.weight(0.7f),
            )
            OutlinedTextField(
                value = portText,
                onValueChange = onPortTextChange,
                label = { Text("Port") },
                singleLine = true,
                modifier = Modifier.weight(0.3f),
            )
        }

        OutlinedTextField(
            value = username,
            onValueChange = onUsernameChange,
            label = { Text("Username") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )

        OutlinedTextField(
            value = password,
            onValueChange = onPasswordChange,
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
            onValueChange = onDomainChange,
            label = { Text("Domain / Workgroup (任意)") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )

        OutlinedTextField(
            value = shareName,
            onValueChange = onShareNameChange,
            label = { Text("Share Name (空欄時は共有フォルダ一覧を表示)") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )

        OutlinedTextField(
            value = directoryPath,
            onValueChange = onDirectoryPathChange,
            label = { Text("初期フォルダパス (任意)") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )

        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier
                .fillMaxWidth()
                .clickable { onSaveCredentialsChange(!saveCredentials) }
                .padding(vertical = 4.dp),
        ) {
            Checkbox(
                checked = saveCredentials,
                onCheckedChange = onSaveCredentialsChange,
            )
            Spacer(modifier = Modifier.width(4.dp))
            Text(
                text = "接続情報を暗号化して端末に保存する (次回起動時に自動入力)",
                style = MaterialTheme.typography.bodyMedium,
            )
        }

        if (errorMessage != null) {
            Surface(
                color = MaterialTheme.colorScheme.errorContainer,
                shape = RoundedCornerShape(8.dp),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(
                    text = errorMessage,
                    color = MaterialTheme.colorScheme.onErrorContainer,
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.padding(12.dp),
                )
            }
        }

        Button(
            enabled = !loading && host.isNotBlank(),
            onClick = onConnectClick,
            modifier = Modifier.fillMaxWidth(),
        ) {
            if (loading) {
                CircularProgressIndicator(
                    strokeWidth = 2.dp,
                    modifier = Modifier
                        .height(18.dp)
                        .width(18.dp),
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text("接続中...")
            } else {
                Text("SMB サーバーへ接続")
            }
        }
    }
}

@Composable
private fun ShareListBrowserScreen(
    summary: SmbConnectionSummary,
    shares: List<SmbShareInfo>,
    manualShareInput: String,
    onManualShareInputChange: (String) -> Unit,
    loading: Boolean,
    errorMessage: String?,
    onShareSelected: (String) -> Unit,
    onRefreshShares: () -> Unit,
    onDisconnect: () -> Unit,
) {
    Column(modifier = Modifier.fillMaxSize()) {
        ConnectionStatusHeader(
            summary = summary,
            currentLocation = "//${summary.host} (共有フォルダ一覧)",
            onDisconnect = onDisconnect,
        )

        HorizontalDivider()

        if (loading) {
            LinearLoadingBanner()
        }

        if (errorMessage != null) {
            ErrorBanner(errorMessage)
        }

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
                    Column(
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                        modifier = Modifier.padding(12.dp),
                    ) {
                        Text(
                            text = "共有フォルダ名を直接指定して開く",
                            style = MaterialTheme.typography.labelLarge,
                        )
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                            modifier = Modifier.fillMaxWidth(),
                        ) {
                            OutlinedTextField(
                                value = manualShareInput,
                                onValueChange = onManualShareInputChange,
                                label = { Text("Share Name") },
                                singleLine = true,
                                modifier = Modifier.weight(1f),
                            )
                            Button(
                                enabled = !loading && manualShareInput.isNotBlank(),
                                onClick = { onShareSelected(manualShareInput.trim()) },
                            ) {
                                Text("開く")
                            }
                        }
                    }
                }
            }

            item {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween,
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 8.dp),
                ) {
                    Text(
                        text = "共有フォルダ一覧 (${shares.size} 件)",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.SemiBold,
                    )
                    OutlinedButton(
                        enabled = !loading,
                        onClick = onRefreshShares,
                    ) {
                        Text("再取得")
                    }
                }
            }

            if (shares.isEmpty() && !loading) {
                item {
                    Text(
                        text = "表示可能な共有フォルダがありません。上の入力欄から共有フォルダ名を指定して開いてください。",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(vertical = 12.dp),
                    )
                }
            }

            items(shares, key = { it.name }) { share ->
                Card(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable(enabled = !loading) { onShareSelected(share.name) },
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(12.dp),
                        modifier = Modifier.padding(14.dp),
                    ) {
                        TypeBadge(text = "SHARE", background = MaterialTheme.colorScheme.primaryContainer, contentColor = MaterialTheme.colorScheme.onPrimaryContainer)
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = share.name,
                                style = MaterialTheme.typography.titleMedium,
                                fontWeight = FontWeight.Medium,
                            )
                            if (share.comment.isNotBlank()) {
                                Text(
                                    text = share.comment,
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            }
                        }
                        Text(
                            text = "開く →",
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.primary,
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun DirectoryBrowserScreen(
    listing: SmbDirectoryListing,
    loading: Boolean,
    errorMessage: String?,
    onNavigateUp: () -> Unit,
    onRefresh: () -> Unit,
    onDisconnect: () -> Unit,
    onFolderClick: (SmbDirectoryEntry) -> Unit,
    onFileClick: (SmbDirectoryEntry) -> Unit,
) {
    val displayPath = if (listing.directoryPath.isEmpty()) {
        "//${listing.connection.host}/${listing.shareName}/"
    } else {
        "//${listing.connection.host}/${listing.shareName}/${listing.directoryPath}"
    }

    Column(modifier = Modifier.fillMaxSize()) {
        ConnectionStatusHeader(
            summary = listing.connection,
            currentLocation = displayPath,
            onDisconnect = onDisconnect,
        )

        Surface(
            color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.4f),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 8.dp),
            ) {
                OutlinedButton(
                    enabled = !loading,
                    onClick = onNavigateUp,
                ) {
                    val upText = if (listing.directoryPath.isEmpty()) "← 共有一覧へ" else "↑ 上の階層へ"
                    Text(upText)
                }
                Spacer(modifier = Modifier.weight(1f))
                FilledTonalButton(
                    enabled = !loading,
                    onClick = onRefresh,
                ) {
                    Text("更新")
                }
            }
        }

        HorizontalDivider()

        if (loading) {
            LinearLoadingBanner()
        }

        if (errorMessage != null) {
            ErrorBanner(errorMessage)
        }

        LazyColumn(
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp),
            modifier = Modifier.fillMaxSize(),
        ) {
            // フォルダ一覧セクション
            item(key = "section_folders") {
                SectionHeader(title = "フォルダ一覧 (${listing.folders.size} 件)")
            }

            if (listing.folders.isEmpty()) {
                item(key = "empty_folders") {
                    Text(
                        text = "サブフォルダはありません",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(vertical = 4.dp, horizontal = 4.dp),
                    )
                }
            } else {
                items(listing.folders, key = { "dir_${it.name}" }) { folder ->
                    DirectoryEntryCard(
                        entry = folder,
                        enabled = !loading,
                        onClick = { onFolderClick(folder) },
                    )
                }
            }

            item(key = "spacer_between") {
                Spacer(modifier = Modifier.height(10.dp))
            }

            // ファイル一覧セクション
            item(key = "section_files") {
                SectionHeader(title = "ファイル一覧 (${listing.files.size} 件)")
            }

            if (listing.files.isEmpty()) {
                item(key = "empty_files") {
                    Text(
                        text = "ファイルはありません",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(vertical = 4.dp, horizontal = 4.dp),
                    )
                }
            } else {
                items(listing.files, key = { "file_${it.name}" }) { file ->
                    FileEntryCard(
                        entry = file,
                        enabled = !loading,
                        onClick = { onFileClick(file) },
                    )
                }
            }
        }
    }
}

@Composable
private fun ConnectionStatusHeader(
    summary: SmbConnectionSummary,
    currentLocation: String,
    onDisconnect: () -> Unit,
) {
    Surface(
        tonalElevation = 2.dp,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(
            verticalArrangement = Arrangement.spacedBy(4.dp),
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 10.dp),
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = currentLocation,
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.SemiBold,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                    val encLabel = if (summary.isEncrypted) {
                        "暗号化通信 (${summary.negotiatedCipher})"
                    } else {
                        "署名通信"
                    }
                    Text(
                        text = "${summary.negotiatedDialect} | $encLabel",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                OutlinedButton(onClick = onDisconnect) {
                    Text("切断")
                }
            }
        }
    }
}

@Composable
private fun SectionHeader(title: String) {
    Text(
        text = title,
        style = MaterialTheme.typography.titleSmall,
        fontWeight = FontWeight.Bold,
        color = MaterialTheme.colorScheme.primary,
        modifier = Modifier.padding(vertical = 4.dp),
    )
}

@Composable
private fun DirectoryEntryCard(
    entry: SmbDirectoryEntry,
    enabled: Boolean,
    onClick: () -> Unit,
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(enabled = enabled, onClick = onClick),
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp),
            modifier = Modifier.padding(horizontal = 14.dp, vertical = 12.dp),
        ) {
            TypeBadge(
                text = "DIR",
                background = MaterialTheme.colorScheme.secondaryContainer,
                contentColor = MaterialTheme.colorScheme.onSecondaryContainer,
            )
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = entry.name,
                    style = MaterialTheme.typography.bodyLarge,
                    fontWeight = FontWeight.Medium,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    text = "更新: ${SmbFormatUtils.formatEpochMillisUtc(entry.lastWriteTimeMillis)}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Text(
                text = "→",
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun FileEntryCard(
    entry: SmbDirectoryEntry,
    enabled: Boolean,
    onClick: () -> Unit,
) {
    val previewType = remember(entry.name) { SmbPreviewType.fromFileName(entry.name) }
    val (badgeBg, badgeFg) = when (previewType) {
        SmbPreviewType.TEXT -> Color(0xFFE3F2FD) to Color(0xFF0D47A1)
        SmbPreviewType.IMAGE -> Color(0xFFE8F5E9) to Color(0xFF1B5E20)
        SmbPreviewType.VIDEO -> Color(0xFFFCE4EC) to Color(0xFF880E4F)
        SmbPreviewType.OTHER -> MaterialTheme.colorScheme.surfaceVariant to MaterialTheme.colorScheme.onSurfaceVariant
    }

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(enabled = enabled, onClick = onClick),
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp),
            modifier = Modifier.padding(horizontal = 14.dp, vertical = 12.dp),
        ) {
            TypeBadge(
                text = previewType.label,
                background = badgeBg,
                contentColor = badgeFg,
            )
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = entry.name,
                    style = MaterialTheme.typography.bodyLarge,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    text = "${SmbFormatUtils.formatBytes(entry.size)}  •  ${SmbFormatUtils.formatEpochMillisUtc(entry.lastWriteTimeMillis)}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Text(
                text = "表示",
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.primary,
            )
        }
    }
}

@Composable
private fun TypeBadge(
    text: String,
    background: Color,
    contentColor: Color,
) {
    Surface(
        color = background,
        shape = RoundedCornerShape(6.dp),
    ) {
        Text(
            text = text,
            color = contentColor,
            style = MaterialTheme.typography.labelSmall,
            fontWeight = FontWeight.Bold,
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
        )
    }
}

@Composable
private fun LinearLoadingBanner() {
    Box(
        contentAlignment = Alignment.Center,
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 8.dp),
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            CircularProgressIndicator(
                strokeWidth = 2.dp,
                modifier = Modifier
                    .height(16.dp)
                    .width(16.dp),
            )
            Text(
                text = "通信中...",
                style = MaterialTheme.typography.bodySmall,
            )
        }
    }
}

@Composable
private fun ErrorBanner(message: String) {
    Surface(
        color = MaterialTheme.colorScheme.errorContainer,
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 8.dp),
        shape = RoundedCornerShape(8.dp),
    ) {
        Text(
            text = message,
            color = MaterialTheme.colorScheme.onErrorContainer,
            style = MaterialTheme.typography.bodySmall,
            modifier = Modifier.padding(12.dp),
        )
    }
}
