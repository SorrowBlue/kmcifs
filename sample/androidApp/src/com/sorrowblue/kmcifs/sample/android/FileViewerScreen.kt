package com.sorrowblue.kmcifs.sample.android

import android.graphics.BitmapFactory
import android.net.Uri
import android.view.ViewGroup
import android.widget.FrameLayout
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
import com.sorrowblue.kmcifs.sample.SmbHttpRangeServer
import com.sorrowblue.kmcifs.sample.SmbPreviewType
import com.sorrowblue.kmcifs.sample.SmbRandomAccessStream
import com.sorrowblue.kmcifs.sample.SmbTextFileContent
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.videolan.libvlc.LibVLC
import org.videolan.libvlc.Media
import org.videolan.libvlc.MediaPlayer
import org.videolan.libvlc.util.VLCVideoLayout

/**
 * Viewer screen that displays the contents of a selected remote SMB file (text, image, or video).
 */
@Composable
fun FileViewerScreen(
    session: SmbBrowserSession,
    shareName: String,
    filePath: String,
    entry: SmbDirectoryEntry,
    onBack: () -> Unit,
) {
    val initialType = remember(shareName, filePath) { SmbPreviewType.fromFileName(entry.name) }
    var activeType by remember(shareName, filePath) { mutableStateOf(initialType) }

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
 * Streams video files (including large OpenDML `.avi` files and DTS/AC-3 audio tracks) over SMB
 * by combining [LibVLC] / [MediaPlayer] with the local loopback HTTP Range server ([SmbHttpRangeServer])
 * and the multi-block LRU cache + asynchronous prefetcher in [SmbRandomAccessStream].
 *
 * Serving the stream via `http://127.0.0.1` instead of `fd://` keeps VLC's `STREAM_CAN_FASTSEEK` disabled
 * (treating it as a network stream), avoiding a full scan of multi-gigabyte `AVIX` / `idx1` indices before
 * playback starts.
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
    var httpServerRef by remember(shareName, filePath) { mutableStateOf<SmbHttpRangeServer?>(null) }
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
            serverToClose?.markClosed()

            scope.launch(Dispatchers.IO + NonCancellable) {
                runCatching {
                    playerToRelease?.stop()
                    playerToRelease?.detachViews()
                    playerToRelease?.release()
                }
                runCatching { vlcToRelease?.release() }
                runCatching { serverToClose?.closeSuspend() }
                runCatching { streamToClose?.closeSuspend() }
            }
        }
    }

    LaunchedEffect(shareName, filePath) {
        openingHandle = true
        errorMessage = null
        var openedStream: SmbRandomAccessStream? = null
        var openedServer: SmbHttpRangeServer? = null
        var openedVlc: LibVLC? = null
        var openedPlayer: MediaPlayer? = null

        val result = runCatching {
            withContext(Dispatchers.IO) {
                val stream = session.openRandomAccessStream(
                    shareName = shareName,
                    filePath = filePath,
                    cacheWindowBytes = 256 * 1024,
                )
                openedStream = stream

                val httpServer = SmbHttpRangeServer.start(
                    stream = stream,
                    fileName = entry.name,
                )
                openedServer = httpServer

                val libVlc = LibVLC(
                    context.applicationContext,
                    arrayListOf(
                        "--network-caching=1200",
                        "--file-caching=1200",
                        "--avi-index=2",
                    ),
                )
                openedVlc = libVlc

                val mediaPlayer = MediaPlayer(libVlc)
                openedPlayer = mediaPlayer
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
                openedStream?.markClosed()
                openedServer?.markClosed()
                withContext(Dispatchers.IO + NonCancellable) {
                    runCatching { openedPlayer?.release() }
                    runCatching { openedVlc?.release() }
                    runCatching { openedServer?.closeSuspend() }
                    runCatching { openedStream?.closeSuspend() }
                }
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
    val httpServer: SmbHttpRangeServer,
    val libVlc: LibVLC,
    val mediaPlayer: MediaPlayer,
)

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
