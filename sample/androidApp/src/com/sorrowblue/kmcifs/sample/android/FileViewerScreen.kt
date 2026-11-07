package com.sorrowblue.kmcifs.sample.android

import android.graphics.BitmapFactory
import android.net.Uri
import android.view.ViewGroup
import android.widget.FrameLayout
import java.io.BufferedOutputStream
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.gestures.detectTransformGestures
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Slider
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableLongStateOf
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
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import com.sorrowblue.kmcifs.client.protocol.SmbDirectoryEntry
import com.sorrowblue.kmcifs.sample.SmbBrowserSession
import com.sorrowblue.kmcifs.sample.SmbFormatUtils
import com.sorrowblue.kmcifs.sample.SmbPreviewType
import com.sorrowblue.kmcifs.sample.SmbRandomAccessStream
import com.sorrowblue.kmcifs.sample.SmbTextFileContent
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import org.videolan.libvlc.LibVLC
import org.videolan.libvlc.Media
import org.videolan.libvlc.MediaPlayer
import org.videolan.libvlc.util.VLCVideoLayout

/**
 * 選択されたリモートファイル（テキスト・画像・動画）の中身を表示するビューア画面。
 */
@Composable
fun FileViewerScreen(
    session: SmbBrowserSession,
    shareName: String,
    filePath: String,
    entry: SmbDirectoryEntry,
    onBack: () -> Unit,
) {
    val initialType = remember(entry.name) { SmbPreviewType.fromFileName(entry.name) }
    var activeType by remember(entry.name) { mutableStateOf(initialType) }

    Column(modifier = Modifier.fillMaxSize()) {
        Surface(
            tonalElevation = 3.dp,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Column(modifier = Modifier.padding(horizontal = 16.dp, vertical = 12.dp)) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    OutlinedButton(onClick = onBack) {
                        Text("← 一覧へ戻る")
                    }
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = entry.name,
                            style = MaterialTheme.typography.titleMedium,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                        Text(
                            text = "//$shareName/$filePath (${SmbFormatUtils.formatBytes(entry.size)})",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }
                }
            }
        }

        HorizontalDivider()

        Box(
            modifier = Modifier
                .fillMaxSize()
                .weight(1f),
        ) {
            when (activeType) {
                SmbPreviewType.TEXT -> TextFilePreviewContent(
                    session = session,
                    shareName = shareName,
                    filePath = filePath,
                )
                SmbPreviewType.IMAGE -> ImageFilePreviewContent(
                    session = session,
                    shareName = shareName,
                    filePath = filePath,
                    entry = entry,
                )
                SmbPreviewType.VIDEO -> VideoFilePreviewContent(
                    session = session,
                    shareName = shareName,
                    filePath = filePath,
                    entry = entry,
                )
                SmbPreviewType.OTHER -> UnsupportedFileTypePrompt(
                    entry = entry,
                    onOpenAsText = { activeType = SmbPreviewType.TEXT },
                    onOpenAsImage = { activeType = SmbPreviewType.IMAGE },
                    onOpenAsVideo = { activeType = SmbPreviewType.VIDEO },
                )
            }
        }
    }
}

@Composable
private fun TextFilePreviewContent(
    session: SmbBrowserSession,
    shareName: String,
    filePath: String,
) {
    var loading by remember(shareName, filePath) { mutableStateOf(true) }
    var errorMessage by remember(shareName, filePath) { mutableStateOf<String?>(null) }
    var content by remember(shareName, filePath) { mutableStateOf<SmbTextFileContent?>(null) }
    var wrapLines by remember { mutableStateOf(true) }

    LaunchedEffect(shareName, filePath) {
        loading = true
        errorMessage = null
        val result = runCatching {
            withContext(Dispatchers.IO) {
                session.readTextFile(shareName = shareName, filePath = filePath)
            }
        }
        result.fold(
            onSuccess = { content = it },
            onFailure = { errorMessage = it.message ?: it::class.simpleName ?: "Unknown error" },
        )
        loading = false
    }

    when {
        loading -> LoadingIndicatorBox(message = "テキストファイルを読み込み中...")
        errorMessage != null -> ErrorMessageBox(message = errorMessage!!)
        content != null -> {
            val data = content!!
            Column(modifier = Modifier.fillMaxSize()) {
                Surface(
                    color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween,
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 16.dp, vertical = 6.dp),
                    ) {
                        val sizeNote = if (data.isTruncated) {
                            "先頭 ${SmbFormatUtils.formatBytes(data.loadedBytes.toLong())} / 全 ${SmbFormatUtils.formatBytes(data.totalSize)} を表示中"
                        } else {
                            "${SmbFormatUtils.formatBytes(data.loadedBytes.toLong())} (${data.text.lines().size} 行)"
                        }
                        Text(
                            text = sizeNote,
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        FilledTonalButton(onClick = { wrapLines = !wrapLines }) {
                            Text(if (wrapLines) "折り返し: ON" else "折り返し: OFF")
                        }
                    }
                }
                HorizontalDivider()

                val verticalScroll = rememberScrollState()
                val horizontalScroll = rememberScrollState()
                val textModifier = if (wrapLines) {
                    Modifier
                        .fillMaxSize()
                        .verticalScroll(verticalScroll)
                        .padding(16.dp)
                } else {
                    Modifier
                        .fillMaxSize()
                        .verticalScroll(verticalScroll)
                        .horizontalScroll(horizontalScroll)
                        .padding(16.dp)
                }

                SelectionContainer(modifier = Modifier.fillMaxSize()) {
                    Text(
                        text = data.text,
                        fontFamily = FontFamily.Monospace,
                        style = MaterialTheme.typography.bodyMedium,
                        softWrap = wrapLines,
                        modifier = textModifier,
                    )
                }
            }
        }
    }
}

@Composable
private fun ImageFilePreviewContent(
    session: SmbBrowserSession,
    shareName: String,
    filePath: String,
    entry: SmbDirectoryEntry,
) {
    var loading by remember(shareName, filePath) { mutableStateOf(true) }
    var loadedBytes by remember(shareName, filePath) { mutableLongStateOf(0L) }
    var totalBytes by remember(shareName, filePath) { mutableLongStateOf(entry.size) }
    var errorMessage by remember(shareName, filePath) { mutableStateOf<String?>(null) }
    var imageBitmap by remember(shareName, filePath) { mutableStateOf<ImageBitmap?>(null) }

    var scale by remember(shareName, filePath) { mutableFloatStateOf(1f) }
    var offset by remember(shareName, filePath) { mutableStateOf(Offset.Zero) }

    LaunchedEffect(shareName, filePath) {
        loading = true
        errorMessage = null
        val result = runCatching {
            withContext(Dispatchers.IO) {
                val bytes = session.readFileBytes(
                    shareName = shareName,
                    filePath = filePath,
                    onProgress = { loaded, total ->
                        loadedBytes = loaded
                        totalBytes = total
                    },
                )
                val bitmap = BitmapFactory.decodeByteArray(bytes, 0, bytes.size)
                    ?: error("画像データとしてデコードできませんでした (${bytes.size} bytes)")
                bitmap.asImageBitmap()
            }
        }
        result.fold(
            onSuccess = { imageBitmap = it },
            onFailure = { errorMessage = it.message ?: it::class.simpleName ?: "Unknown error" },
        )
        loading = false
    }

    when {
        loading -> DownloadProgressBox(
            title = "画像ファイルを読み込み中...",
            loadedBytes = loadedBytes,
            totalBytes = totalBytes,
        )
        errorMessage != null -> ErrorMessageBox(message = errorMessage!!)
        imageBitmap != null -> {
            val bitmap = imageBitmap!!
            Column(modifier = Modifier.fillMaxSize()) {
                Surface(
                    color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween,
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 16.dp, vertical = 6.dp),
                    ) {
                        Text(
                            text = "${bitmap.width} × ${bitmap.height} px  (倍率 ${(scale * 100).toInt()}%)",
                            style = MaterialTheme.typography.labelMedium,
                        )
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            OutlinedButton(
                                onClick = {
                                    scale = (scale - 0.5f).coerceAtLeast(1f)
                                    if (scale == 1f) offset = Offset.Zero
                                },
                            ) {
                                Text("－")
                            }
                            OutlinedButton(
                                onClick = {
                                    scale = 1f
                                    offset = Offset.Zero
                                },
                            ) {
                                Text("1:1")
                            }
                            OutlinedButton(
                                onClick = {
                                    scale = (scale + 0.5f).coerceAtMost(5f)
                                },
                            ) {
                                Text("＋")
                            }
                        }
                    }
                }
                HorizontalDivider()

                Box(
                    contentAlignment = Alignment.Center,
                    modifier = Modifier
                        .fillMaxSize()
                        .background(Color(0xFF121212))
                        .clipToBounds()
                        .pointerInput(shareName, filePath) {
                            detectTransformGestures { _, pan, zoom, _ ->
                                val newScale = (scale * zoom).coerceIn(1f, 5f)
                                scale = newScale
                                offset = if (newScale > 1f) {
                                    offset + pan
                                } else {
                                    Offset.Zero
                                }
                            }
                        },
                ) {
                    Image(
                        bitmap = bitmap,
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
    }
}

/**
 * LibVLC ([LibVLC] / [MediaPlayer]) とローカルループバック HTTP Range ストリームサーバー ([SmbLocalHttpStreamServer])、
 * および [SmbRandomAccessStream] のマルチブロックキャッシュ＋非同期先読みを組み合わせ、
 * OpenDML 大容量 `.avi`（9.6GB 等）や DTS / AC-3 音声を含む動画ファイルを即座に SMB ストリーミング再生するコンポーネント。
 *
 * `fd://` ではなく `http://127.0.0.1` で LibVLC に渡すことで、VLC の `STREAM_CAN_FASTSEEK` を `false`（ネットワークストリーム扱い）にし、
 * 再生開始前に 9.6GB 全体の `AVIX` / `idx1` インデックス（数十MB〜）を全スキャンしてしまう現象を防いで即座に再生を開始させる。
 */
@Composable
private fun VideoFilePreviewContent(
    session: SmbBrowserSession,
    shareName: String,
    filePath: String,
    entry: SmbDirectoryEntry,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    var openingHandle by remember(shareName, filePath) { mutableStateOf(true) }
    var errorMessage by remember(shareName, filePath) { mutableStateOf<String?>(null) }

    var activeStream by remember(shareName, filePath) { mutableStateOf<SmbRandomAccessStream?>(null) }
    var httpServerRef by remember(shareName, filePath) { mutableStateOf<SmbLocalHttpStreamServer?>(null) }
    var libVlcRef by remember(shareName, filePath) { mutableStateOf<LibVLC?>(null) }
    var vlcPlayerRef by remember(shareName, filePath) { mutableStateOf<MediaPlayer?>(null) }

    var isPlaying by remember(shareName, filePath) { mutableStateOf(false) }
    var currentTimeMs by remember(shareName, filePath) { mutableLongStateOf(0L) }
    var durationMs by remember(shareName, filePath) { mutableLongStateOf(0L) }
    var isDraggingSlider by remember(shareName, filePath) { mutableStateOf(false) }
    var sliderPosition by remember(shareName, filePath) { mutableFloatStateOf(0f) }

    var fetchedBytes by remember(shareName, filePath) { mutableLongStateOf(0L) }
    var lastReadOffset by remember(shareName, filePath) { mutableLongStateOf(0L) }

    DisposableEffect(shareName, filePath) {
        onDispose {
            val streamToClose = activeStream
            val serverToClose = httpServerRef
            val playerToRelease = vlcPlayerRef
            val vlcToRelease = libVlcRef

            activeStream = null
            httpServerRef = null
            vlcPlayerRef = null
            libVlcRef = null

            streamToClose?.markClosed()
            serverToClose?.close()

            scope.launch(Dispatchers.IO + NonCancellable) {
                runCatching {
                    playerToRelease?.stop()
                    playerToRelease?.detachViews()
                    playerToRelease?.release()
                }
                runCatching { vlcToRelease?.release() }
                streamToClose?.closeSuspend()
            }
        }
    }

    LaunchedEffect(shareName, filePath) {
        openingHandle = true
        errorMessage = null
        val result = runCatching {
            withContext(Dispatchers.IO) {
                val stream = session.openRandomAccessStream(
                    shareName = shareName,
                    filePath = filePath,
                    cacheWindowBytes = 256 * 1024,
                )

                val httpServer = SmbLocalHttpStreamServer(
                    stream = stream,
                    fileName = entry.name,
                ).apply { start() }

                val libVlc = LibVLC(
                    context.applicationContext,
                    arrayListOf(
                        "--network-caching=1200",
                        "--file-caching=1200",
                        "--avi-index=2",
                    ),
                )
                val mediaPlayer = MediaPlayer(libVlc)
                mediaPlayer.setEventListener { event ->
                    when (event.type) {
                        MediaPlayer.Event.Playing -> isPlaying = true
                        MediaPlayer.Event.Paused,
                        MediaPlayer.Event.Stopped,
                        MediaPlayer.Event.EndReached -> isPlaying = false
                        MediaPlayer.Event.LengthChanged -> {
                            if (event.lengthChanged > 0L) {
                                durationMs = event.lengthChanged
                            }
                        }
                        MediaPlayer.Event.TimeChanged -> {
                            val t = event.timeChanged
                            if (t >= 0L) {
                                currentTimeMs = t
                            }
                        }
                        MediaPlayer.Event.EncounteredError -> {
                            if (!stream.isClosed) {
                                errorMessage = "LibVLC で動画の再生中にエラーが発生しました"
                            }
                        }
                    }
                }

                val media = Media(libVlc, Uri.parse(httpServer.streamUrl)).apply {
                    addOption(":network-caching=1200")
                    addOption(":avi-index=2")
                }
                mediaPlayer.media = media
                media.release()

                VlcSessionBundle(
                    stream = stream,
                    httpServer = httpServer,
                    libVlc = libVlc,
                    mediaPlayer = mediaPlayer,
                )
            }
        }
        result.fold(
            onSuccess = { bundle ->
                activeStream = bundle.stream
                httpServerRef = bundle.httpServer
                libVlcRef = bundle.libVlc
                vlcPlayerRef = bundle.mediaPlayer
            },
            onFailure = { e ->
                errorMessage = e.message ?: e::class.simpleName ?: "動画ストリームを開けませんでした"
            },
        )
        openingHandle = false
    }

    // 500ms 間隔でストリーミング転送量とシークバー位置を更新
    LaunchedEffect(activeStream, vlcPlayerRef) {
        val stream = activeStream ?: return@LaunchedEffect
        val player = vlcPlayerRef ?: return@LaunchedEffect
        while (isActive) {
            fetchedBytes = stream.totalFetchedBytes
            lastReadOffset = stream.lastReadPosition
            val len = player.length
            if (len > 0L) durationMs = len
            val time = player.time
            if (time >= 0L) currentTimeMs = time
            if (!isDraggingSlider && durationMs > 0L) {
                sliderPosition = (currentTimeMs.toFloat() / durationMs.toFloat()).coerceIn(0f, 1f)
            }
            delay(500L)
        }
    }

    when {
        openingHandle -> LoadingIndicatorBox(message = "SMB ストリーミング接続を開始中 (LibVLC)...")
        errorMessage != null -> ErrorMessageBox(message = errorMessage!!)
        vlcPlayerRef != null -> {
            val player = vlcPlayerRef!!
            Column(modifier = Modifier.fillMaxSize()) {
                Surface(
                    color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween,
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 16.dp, vertical = 6.dp),
                    ) {
                        Text(
                            text = "SMB ストリーミング再生 (LibVLC)",
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.primary,
                        )
                        Text(
                            text = "取得済み: ${SmbFormatUtils.formatBytes(fetchedBytes)} (読取位置: ${SmbFormatUtils.formatBytes(lastReadOffset)})",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
                HorizontalDivider()

                Box(
                    contentAlignment = Alignment.Center,
                    modifier = Modifier
                        .fillMaxWidth()
                        .weight(1f)
                        .background(Color.Black),
                ) {
                    AndroidView(
                        factory = { ctx ->
                            VLCVideoLayout(ctx).apply {
                                layoutParams = FrameLayout.LayoutParams(
                                    ViewGroup.LayoutParams.MATCH_PARENT,
                                    ViewGroup.LayoutParams.MATCH_PARENT,
                                )
                                player.attachViews(this, null, true, false)
                                player.play()
                            }
                        },
                        modifier = Modifier.fillMaxSize(),
                    )
                }

                HorizontalDivider()
                Surface(
                    tonalElevation = 2.dp,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 16.dp, vertical = 8.dp),
                    ) {
                        if (durationMs > 0L) {
                            Slider(
                                value = sliderPosition,
                                onValueChange = { value ->
                                    isDraggingSlider = true
                                    sliderPosition = value
                                },
                                onValueChangeFinished = {
                                    val targetMs = (sliderPosition * durationMs).toLong().coerceIn(0L, durationMs)
                                    player.time = targetMs
                                    currentTimeMs = targetMs
                                    isDraggingSlider = false
                                },
                                modifier = Modifier.fillMaxWidth(),
                            )
                        }
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.SpaceBetween,
                            modifier = Modifier.fillMaxWidth(),
                        ) {
                            Text(
                                text = "${SmbFormatUtils.formatDurationMillis(currentTimeMs)} / ${
                                    if (durationMs > 0L) SmbFormatUtils.formatDurationMillis(durationMs) else "--:--"
                                }",
                                style = MaterialTheme.typography.bodySmall,
                            )
                            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                OutlinedButton(
                                    onClick = {
                                        val next = (player.time - 10_000L).coerceAtLeast(0L)
                                        player.time = next
                                        currentTimeMs = next
                                    },
                                ) {
                                    Text("-10秒")
                                }
                                Button(
                                    onClick = {
                                        if (player.isPlaying) {
                                            player.pause()
                                            isPlaying = false
                                        } else {
                                            player.play()
                                            isPlaying = true
                                        }
                                    },
                                ) {
                                    Text(if (isPlaying) "一時停止" else "再生")
                                }
                                OutlinedButton(
                                    onClick = {
                                        val maxTime = if (durationMs > 0L) durationMs else Long.MAX_VALUE
                                        val next = (player.time + 10_000L).coerceAtMost(maxTime)
                                        player.time = next
                                        currentTimeMs = next
                                    },
                                ) {
                                    Text("+10秒")
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

private class VlcSessionBundle(
    val stream: SmbRandomAccessStream,
    val httpServer: SmbLocalHttpStreamServer,
    val libVlc: LibVLC,
    val mediaPlayer: MediaPlayer,
)

/**
 * `127.0.0.1` 上で動作する軽量な HTTP 1.1 Range 対応ストリーミングサーバー。
 *
 * LibVLC に `http://127.0.0.1:<port>/<fileName>` を渡すことで：
 * 1. `STREAM_CAN_SEEK = true`（HTTP `Range: bytes=...` による 64bit シーク対応）
 * 2. `STREAM_CAN_FASTSEEK = false`（ネットワークストリームとして扱わせ、9.6GB の AVI ファイルを開いた際に
 *    数十MBのインデックスチャンク群を再生前に全スキャンするのを防ぎ、先頭チャンクから即座に再生を開始させる）
 * を両立する。
 */
private class SmbLocalHttpStreamServer(
    private val stream: SmbRandomAccessStream,
    fileName: String,
) : AutoCloseable {

    private val serverSocket = ServerSocket(0, 16, InetAddress.getLoopbackAddress())
    private val encodedName = Uri.encode(fileName.ifEmpty { "video.mp4" })
    private val mimeType = guessMimeType(fileName)

    val streamUrl: String = "http://127.0.0.1:${serverSocket.localPort}/$encodedName"

    @kotlin.concurrent.Volatile
    private var closed = false

    fun start() {
        Thread({
            while (!closed) {
                val client = try {
                    serverSocket.accept()
                } catch (e: Throwable) {
                    break
                }
                Thread({ handleClient(client) }, "SmbHttpWorker").apply {
                    isDaemon = true
                    start()
                }
            }
        }, "SmbHttpAccept").apply {
            isDaemon = true
            start()
        }
    }

    private fun handleClient(socket: Socket) {
        socket.use { sock ->
            runCatching {
                sock.tcpNoDelay = true
                val reader = BufferedReader(InputStreamReader(sock.getInputStream(), Charsets.US_ASCII))
                val requestLine = reader.readLine() ?: return
                val isHead = requestLine.startsWith("HEAD ", ignoreCase = true)

                var rangeHeader: String? = null
                while (true) {
                    val line = reader.readLine() ?: break
                    if (line.isEmpty()) break
                    if (line.startsWith("Range:", ignoreCase = true)) {
                        rangeHeader = line.substringAfter(':').trim()
                    }
                }

                val totalSize = stream.size
                var startOffset = 0L
                var endOffset = if (totalSize > 0L) totalSize - 1L else Long.MAX_VALUE
                var isPartial = false

                if (rangeHeader != null && rangeHeader.startsWith("bytes=", ignoreCase = true)) {
                    val spec = rangeHeader.substringAfter('=').substringBefore(',').trim()
                    val dashIdx = spec.indexOf('-')
                    if (dashIdx >= 0) {
                        val startPart = spec.substring(0, dashIdx).trim()
                        val endPart = spec.substring(dashIdx + 1).trim()
                        if (startPart.isNotEmpty()) {
                            startOffset = startPart.toLongOrNull() ?: 0L
                            if (endPart.isNotEmpty()) {
                                endOffset = endPart.toLongOrNull() ?: endOffset
                            }
                            isPartial = true
                        } else if (endPart.isNotEmpty() && totalSize > 0L) {
                            val suffixLen = endPart.toLongOrNull() ?: 0L
                            startOffset = (totalSize - suffixLen).coerceAtLeast(0L)
                            endOffset = totalSize - 1L
                            isPartial = true
                        }
                    }
                }

                if (totalSize > 0L) {
                    if (startOffset >= totalSize) {
                        val out = sock.getOutputStream()
                        val err = "HTTP/1.1 416 Range Not Satisfiable\r\nContent-Range: bytes */$totalSize\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        out.write(err.encodeToByteArray())
                        out.flush()
                        return
                    }
                    endOffset = endOffset.coerceAtMost(totalSize - 1L)
                }

                val contentLength = if (totalSize > 0L) (endOffset - startOffset + 1L) else -1L
                val statusLine = if (isPartial) "HTTP/1.1 206 Partial Content" else "HTTP/1.1 200 OK"
                val headers = buildString {
                    append(statusLine).append("\r\n")
                    append("Content-Type: ").append(mimeType).append("\r\n")
                    append("Accept-Ranges: bytes\r\n")
                    if (isPartial && totalSize > 0L) {
                        append("Content-Range: bytes ").append(startOffset).append('-').append(endOffset).append('/').append(totalSize).append("\r\n")
                    }
                    if (contentLength >= 0L) {
                        append("Content-Length: ").append(contentLength).append("\r\n")
                    }
                    append("Connection: close\r\n\r\n")
                }

                val output = BufferedOutputStream(sock.getOutputStream(), 65536)
                output.write(headers.encodeToByteArray())
                output.flush()

                if (isHead) return

                val buffer = ByteArray(65536)
                var currentPos = startOffset
                while (!closed && !stream.isClosed && (totalSize <= 0L || currentPos <= endOffset)) {
                    val toRead = if (totalSize > 0L) {
                        minOf(buffer.size.toLong(), endOffset - currentPos + 1L).toInt()
                    } else {
                        buffer.size
                    }
                    if (toRead <= 0) break

                    val readBytes = runBlocking(Dispatchers.IO) {
                        stream.readAt(currentPos, buffer, 0, toRead)
                    }
                    if (readBytes <= 0) break

                    output.write(buffer, 0, readBytes)
                    currentPos += readBytes
                }
                output.flush()
            }
        }
    }

    override fun close() {
        closed = true
        runCatching { serverSocket.close() }
    }

    companion object {
        private fun guessMimeType(fileName: String): String {
            val ext = fileName.substringAfterLast('.', "").lowercase()
            return when (ext) {
                "avi" -> "video/x-msvideo"
                "mp4", "m4v" -> "video/mp4"
                "mkv" -> "video/x-matroska"
                "webm" -> "video/webm"
                "mov" -> "video/quicktime"
                "ts" -> "video/mp2t"
                else -> "application/octet-stream"
            }
        }
    }
}

@Composable
private fun UnsupportedFileTypePrompt(
    entry: SmbDirectoryEntry,
    onOpenAsText: () -> Unit,
    onOpenAsImage: () -> Unit,
    onOpenAsVideo: () -> Unit,
) {
    Box(
        contentAlignment = Alignment.Center,
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
    ) {
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(
                verticalArrangement = Arrangement.spacedBy(12.dp),
                modifier = Modifier.padding(20.dp),
            ) {
                Text(
                    text = "表示形式の選択",
                    style = MaterialTheme.typography.titleMedium,
                )
                Text(
                    text = "「${entry.name}」(${SmbFormatUtils.formatBytes(entry.size)}) の拡張子から自動判定できませんでした。開く形式を選択してください。",
                    style = MaterialTheme.typography.bodyMedium,
                )
                Button(
                    onClick = onOpenAsText,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text("テキストとして表示")
                }
                FilledTonalButton(
                    onClick = onOpenAsImage,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text("画像として表示")
                }
                FilledTonalButton(
                    onClick = onOpenAsVideo,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text("動画としてストリーミング再生")
                }
            }
        }
    }
}

@Composable
private fun LoadingIndicatorBox(message: String) {
    Box(
        contentAlignment = Alignment.Center,
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
    ) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            CircularProgressIndicator()
            Text(text = message, style = MaterialTheme.typography.bodyMedium)
        }
    }
}

@Composable
private fun DownloadProgressBox(
    title: String,
    loadedBytes: Long,
    totalBytes: Long,
) {
    Box(
        contentAlignment = Alignment.Center,
        modifier = Modifier
            .fillMaxSize()
            .padding(32.dp),
    ) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(12.dp),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(text = title, style = MaterialTheme.typography.titleMedium)
            if (totalBytes > 0L) {
                val progress = (loadedBytes.toFloat() / totalBytes.toFloat()).coerceIn(0f, 1f)
                val percent = (progress * 100).toInt()
                LinearProgressIndicator(
                    progress = { progress },
                    modifier = Modifier.fillMaxWidth(),
                )
                Text(
                    text = "${SmbFormatUtils.formatBytes(loadedBytes)} / ${SmbFormatUtils.formatBytes(totalBytes)} ($percent%)",
                    style = MaterialTheme.typography.bodySmall,
                )
            } else {
                LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                Text(
                    text = "${SmbFormatUtils.formatBytes(loadedBytes)} 読み込み済み",
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        }
    }
}

@Composable
private fun ErrorMessageBox(message: String) {
    Box(
        contentAlignment = Alignment.Center,
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
    ) {
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(
                verticalArrangement = Arrangement.spacedBy(8.dp),
                modifier = Modifier.padding(16.dp),
            ) {
                Text(
                    text = "読み込みエラー",
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.error,
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = message,
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
        }
    }
}
