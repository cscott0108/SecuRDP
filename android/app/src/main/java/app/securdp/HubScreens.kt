package app.securdp

import android.annotation.SuppressLint
import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.graphics.BitmapFactory
import android.net.Uri
import android.net.http.SslError
import android.provider.OpenableColumns
import android.util.LruCache
import android.webkit.MimeTypeMap
import android.webkit.SslErrorHandler
import android.webkit.WebChromeClient
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.Toast
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.Checkbox
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.zIndex
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.FileProvider
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext
import java.io.File
import java.text.DateFormat
import java.util.Date
import kotlin.concurrent.thread

/** Which screen the app shows; hub screens need a hub session. */
sealed interface Screen {
    data object Main : Screen
    data object Hub : Screen
    data class Files(val folder: String) : Screen
    data class Web(val service: HubService) : Screen
}

/** The profile and hub offer when the current connection is a hub login. */
fun hubOf(state: TunnelState): Pair<Profile, HubInfo>? = when (state) {
    is TunnelState.Hub -> state.profile to state.info
    is TunnelState.Connected -> state.info?.let { state.profile to it }
    else -> null
}

private val Good = Color(0xFF16A34A)

// ---------------------------------------------------------------- hub screen

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HubScreen(
    profileName: String,
    info: HubInfo,
    onRdp: (String, Boolean) -> Unit,
    onFolder: (String) -> Unit,
    onWeb: (HubService) -> Unit,
    onWebExternal: (HubService) -> Unit,
    onPairLink: (HubService) -> Unit,
    onClose: () -> Unit,
) {
    BackHandler(onBack = onClose)
    var keep by remember { mutableStateOf(false) }
    val external by TunnelManager.externalPages.collectAsStateWithLifecycle()
    Scaffold(topBar = {
        TopAppBar(
            title = { Text(profileName, fontWeight = FontWeight.SemiBold) },
            navigationIcon = { TextButton(onClick = onClose) { Text("‹ Back") } },
            actions = { TextButton(onClick = { TunnelManager.disconnect() }) { Text("Disconnect", color = MaterialTheme.colorScheme.error) } },
        )
    }) { pad ->
        LazyColumn(
            Modifier.fillMaxSize().padding(pad),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            item { ApkUpdateCard(info) }
            if (info.computers.isNotEmpty()) {
                item { SectionTitle("Remote Desktop") }
                items(info.computers) { c ->
                    OutlinedButton(onClick = { onRdp(c.name, keep) }, modifier = Modifier.fillMaxWidth()) {
                        Text("●", color = if (c.online) Good else MaterialTheme.colorScheme.outline)
                        Spacer(Modifier.width(10.dp))
                        Text(c.name, fontWeight = FontWeight.SemiBold, modifier = Modifier.weight(1f))
                        Text(
                            (if (c.online) "online" else "not answering") + (if (c.isDefault) " · default" else ""),
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                }
                item {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(checked = keep, onCheckedChange = { keep = it })
                        Text("Always go straight to the computer I pick", style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
            if (info.folders.isNotEmpty()) {
                item { SectionTitle("Files") }
                items(info.folders) { f ->
                    HubTile("📁", f.name, if (f.writable) "read & write" else "read-only") { onFolder(f.name) }
                }
            }
            if (info.services.isNotEmpty()) {
                item { SectionTitle("Web pages") }
                item {
                    Text(
                        "Tap to open in the app, or open in Chrome through the same tunnel (better for downloads, new tabs and full-size images).",
                        style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                items(info.services) { s ->
                    Column {
                        HubTile("🌐", s.name, s.scheme + " · " + s.path.ifEmpty { "/" }) { onWeb(s) }
                        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End, verticalAlignment = Alignment.CenterVertically) {
                            if (s.name in external) {
                                Text("Open in your browser", style = MaterialTheme.typography.bodySmall, color = Good)
                                TextButton(onClick = { TunnelManager.stopExternal(s.name) }) {
                                    Text("Stop", color = MaterialTheme.colorScheme.error)
                                }
                            }
                            TextButton(onClick = { onWebExternal(s) }) { Text("Open in Chrome ↗") }
                        }
                    }
                }
            }
            if (info.appLinks && info.services.isNotEmpty()) {
                item { SectionTitle("App links") }
                item {
                    Text(
                        "Let an app on this phone (e.g. one running in the background) reach a web page here without logging in. " +
                            "Each link reaches only its own page; remove it any time here or on the hub.",
                        style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                items(info.services) { s ->
                    OutlinedButton(onClick = { onPairLink(s) }, modifier = Modifier.fillMaxWidth()) { Text("🔗 Link an app to ${s.name}…") }
                }
            }
        }
    }
}

@Composable
private fun SectionTitle(t: String) =
    Text(t, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold, modifier = Modifier.padding(top = 8.dp))

@Composable
private fun HubTile(icon: String, title: String, sub: String, onClick: () -> Unit) {
    Card(Modifier.fillMaxWidth().clickable(onClick = onClick)) {
        Row(Modifier.padding(14.dp), verticalAlignment = Alignment.CenterVertically) {
            Text(icon, fontSize = 24.sp)
            Spacer(Modifier.width(12.dp))
            Column {
                Text(title, fontWeight = FontWeight.SemiBold)
                Text(sub, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }
}

// --------------------------------------------------------------- file browser

private val EXT = mapOf(
    "image" to "jpg jpeg png gif bmp webp heic tif tiff",
    "video" to "mp4 m4v mov mkv avi wmv webm mpg mpeg 3gp ts",
    "audio" to "mp3 wav flac m4a aac ogg wma opus",
    "archive" to "zip rar 7z tar gz bz2 xz iso",
    "doc" to "pdf doc docx xls xlsx ppt pptx txt rtf odt ods md csv",
    "app" to "exe msi apk dll",
).mapValues { it.value.split(" ").toSet() }
private val ICON = mapOf("folder" to "📁", "image" to "🖼️", "video" to "🎬", "audio" to "🎵", "archive" to "🗜️", "doc" to "📄", "app" to "⚙️")

private fun ext(name: String) = name.substringAfterLast('.', "").lowercase()
private fun kind(f: HubFile) = if (f.dir) "folder" else EXT.entries.firstOrNull { ext(f.name) in it.value }?.key ?: "file"
private fun icon(f: HubFile) = ICON[kind(f)] ?: "📄"
private fun thumbable(f: HubFile) = !f.dir && (ext(f.name) in EXT.getValue("image") || ext(f.name) in EXT.getValue("video"))
private fun typeLabel(f: HubFile) = if (f.dir) "Folder" else ext(f.name).uppercase().ifEmpty { "File" } + " file"
private fun fmtSize(n: Long): String {
    if (n < 1024) return "$n B"
    var v = n.toDouble()
    for (u in listOf("KB", "MB", "GB", "TB")) {
        v /= 1024
        if (v < 1024) return if (v < 10) "%.1f %s".format(v, u) else "%.0f %s".format(v, u)
    }
    return "%.0f TB".format(v)
}
private fun fmtDate(t: Long) = if (t == 0L) "" else DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT).format(Date(t * 1000))

/** Thumbnails are small JPEGs made on the hub; keep recent ones and limit parallel requests. */
private object Thumbs {
    val cache = LruCache<String, ImageBitmap>(300)
    val gate = Semaphore(3)
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun FilesScreen(folder: String, writableRoots: Set<String>, onClose: () -> Unit) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    val prefs = remember { ctx.getSharedPreferences("files", Context.MODE_PRIVATE) }
    var path by remember { mutableStateOf(folder) }
    var entries by remember { mutableStateOf<List<HubFile>>(emptyList()) }
    var loading by remember { mutableStateOf(true) }
    var busy by remember { mutableStateOf<String?>(null) }
    var view by remember { mutableStateOf(prefs.getString("view", "icons")!!) }
    var sort by remember { mutableStateOf(prefs.getString("sort", "name")!!) }
    var asc by remember { mutableStateOf(true) }
    var menuFor by remember { mutableStateOf<HubFile?>(null) }
    var renaming by remember { mutableStateOf<HubFile?>(null) }
    var deleting by remember { mutableStateOf<HubFile?>(null) }
    var newFolder by remember { mutableStateOf(false) }
    var saveTarget by remember { mutableStateOf<HubFile?>(null) }
    var reload by remember { mutableStateOf(0) }
    val writable = path.substringBefore('/') in writableRoots
    fun full(f: HubFile) = "$path/${f.name}"
    fun toast(m: String) = Toast.makeText(ctx, m, Toast.LENGTH_LONG).show()

    // Keep the tunnel open while browsing (no Remote Desktop needed).
    DisposableEffect(Unit) {
        var h: AutoCloseable? = null
        thread(isDaemon = true) { h = runCatching { TunnelManager.tunnel?.hold() }.getOrNull() }
        onDispose { thread(isDaemon = true) { runCatching { h?.close() } } }
    }
    LaunchedEffect(path, reload) {
        loading = true
        val t = TunnelManager.tunnel
        val r = withContext(Dispatchers.IO) { runCatching { t!!.list(path) } }
        r.onSuccess { entries = it }.onFailure { toast(it.message ?: "Couldn't list the folder") }
        loading = false
    }
    BackHandler { if (path.contains('/')) path = path.substringBeforeLast('/') else onClose() }

    /** Runs a file operation off the main thread with a progress message. */
    fun io(msg: String, done: String? = null, block: suspend (Tunnel) -> Unit) {
        val t = TunnelManager.tunnel ?: return toast("Not connected")
        scope.launch {
            busy = msg
            val r = withContext(Dispatchers.IO) { runCatching { block(t) } }
            busy = null
            r.onSuccess { done?.let(::toast) }.onFailure { toast(it.message ?: "Failed") }
        }
    }

    val saveLauncher = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("*/*")) { uri ->
        val f = saveTarget ?: return@rememberLauncherForActivityResult
        saveTarget = null
        if (uri != null) io("Saving ${f.name}…", "Saved ${f.name}") { t ->
            t.get(full(f)).use { r -> ctx.contentResolver.openOutputStream(uri)!!.use { r.body.copyTo(it) } }
        }
    }
    val uploadLauncher = rememberLauncherForActivityResult(ActivityResultContracts.OpenMultipleDocuments()) { uris ->
        if (uris.isNotEmpty()) io("Uploading ${uris.size} file(s)…", "Uploaded ${uris.size} file(s)") { t ->
            for (u in uris) {
                val (name, size) = nameAndSize(ctx, u)
                ctx.contentResolver.openInputStream(u)!!.use { t.put("$path/$name", size, it) }
            }
            withContext(Dispatchers.Main) { reload++ }
        }
    }

    val shown = remember(entries, sort, asc) {
        val cmp: Comparator<HubFile> = when (sort) {
            "date" -> compareBy { it.mtime }
            "size" -> compareBy { it.size }
            "type" -> compareBy({ typeLabel(it) }, { it.name.lowercase() })
            else -> compareBy { it.name.lowercase() }
        }
        val dirsFirst = compareBy<HubFile> { !it.dir }
        entries.sortedWith(dirsFirst.then(if (asc) cmp else cmp.reversed()))
    }
    val open: (HubFile) -> Unit = { f -> if (f.dir) path = full(f) else menuFor = f }

    Scaffold(topBar = {
        TopAppBar(
            title = { Text(path.replace("/", " › "), maxLines = 1, overflow = TextOverflow.Ellipsis, style = MaterialTheme.typography.titleMedium) },
            navigationIcon = {
                TextButton(onClick = { if (path.contains('/')) path = path.substringBeforeLast('/') else onClose() }) { Text("‹ Back") }
            },
            actions = {
                TextButton(onClick = { reload++ }) { Text("↻") }
                if (writable) TextButton(onClick = { newFolder = true }) { Text("New folder") }
            },
        )
    }, floatingActionButton = {
        // A big, always-visible button: the toolbar row is too narrow on phones.
        if (writable) ExtendedFloatingActionButton(onClick = { uploadLauncher.launch(arrayOf("*/*")) }) { Text("⬆  Upload") }
    }) { pad ->
        Column(Modifier.fillMaxSize().padding(pad)) {
            Row(Modifier.fillMaxWidth().padding(horizontal = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                Choice("View", view, listOf("icons" to "Large icons", "list" to "List", "details" to "Details")) {
                    view = it; prefs.edit().putString("view", it).apply()
                }
                Choice("Sort", sort, listOf("name" to "Name", "date" to "Date modified", "size" to "Size", "type" to "Type")) {
                    if (sort == it) asc = !asc else { sort = it; asc = true }
                    prefs.edit().putString("sort", sort).apply()
                }
            }
            if (loading || busy != null) {
                LinearProgressIndicator(Modifier.fillMaxWidth())
                busy?.let { Text(it, style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(8.dp)) }
            }
            Text(
                if (writable) "${shown.size} items"
                else "${shown.size} items · read-only. To allow uploads, on the hub open Files & Web → Edit this folder → tick \"Allow uploads…\".",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(horizontal = 12.dp),
            )
            when (view) {
                "icons" -> LazyVerticalGrid(
                    GridCells.Adaptive(108.dp), Modifier.fillMaxSize(),
                    contentPadding = PaddingValues(8.dp, 8.dp, 8.dp, 96.dp),
                ) {
                    items(shown, key = { it.name }) { f ->
                        Column(
                            Modifier.padding(4.dp).clip(RoundedCornerShape(8.dp)).clickable { open(f) }.padding(4.dp),
                            horizontalAlignment = Alignment.CenterHorizontally,
                        ) {
                            Thumb("$path/${f.name}", f, 96, 256)
                            Text(f.name, maxLines = 2, overflow = TextOverflow.Ellipsis, style = MaterialTheme.typography.bodySmall)
                        }
                    }
                }
                "list" -> LazyColumn(Modifier.fillMaxSize(), contentPadding = PaddingValues(8.dp, 8.dp, 8.dp, 96.dp)) {
                    items(shown, key = { it.name }) { f ->
                        Row(Modifier.fillMaxWidth().clickable { open(f) }.padding(8.dp), verticalAlignment = Alignment.CenterVertically) {
                            Thumb("$path/${f.name}", f, 36, 96)
                            Spacer(Modifier.width(12.dp))
                            Text(f.name, maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f))
                        }
                    }
                }
                else -> LazyColumn(Modifier.fillMaxSize(), contentPadding = PaddingValues(8.dp, 8.dp, 8.dp, 96.dp)) {
                    item {
                        Row(Modifier.fillMaxWidth().padding(8.dp)) {
                            Header("Name", "name", sort, asc, Modifier.weight(1f)) { if (sort == it) asc = !asc else { sort = it; asc = true } }
                            Header("Modified", "date", sort, asc, Modifier.width(110.dp)) { if (sort == it) asc = !asc else { sort = it; asc = true } }
                            Header("Size", "size", sort, asc, Modifier.width(64.dp)) { if (sort == it) asc = !asc else { sort = it; asc = true } }
                        }
                        HorizontalDivider()
                    }
                    items(shown, key = { it.name }) { f ->
                        Row(Modifier.fillMaxWidth().clickable { open(f) }.padding(8.dp), verticalAlignment = Alignment.CenterVertically) {
                            Row(Modifier.weight(1f), verticalAlignment = Alignment.CenterVertically) {
                                Thumb("$path/${f.name}", f, 28, 96)
                                Spacer(Modifier.width(8.dp))
                                Column {
                                    Text(f.name, maxLines = 1, overflow = TextOverflow.Ellipsis, style = MaterialTheme.typography.bodyMedium)
                                    Text(typeLabel(f), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                                }
                            }
                            Text(fmtDate(f.mtime), style = MaterialTheme.typography.labelSmall, modifier = Modifier.width(110.dp))
                            Text(if (f.dir) "" else fmtSize(f.size), style = MaterialTheme.typography.labelSmall, modifier = Modifier.width(64.dp))
                        }
                        HorizontalDivider()
                    }
                }
            }
        }
    }

    menuFor?.let { f ->
        AlertDialog(
            onDismissRequest = { menuFor = null },
            title = { Text(f.name, maxLines = 2, overflow = TextOverflow.Ellipsis) },
            text = {
                Column {
                    Text("${typeLabel(f)} · ${fmtSize(f.size)} · ${fmtDate(f.mtime)}", style = MaterialTheme.typography.bodySmall)
                    Spacer(Modifier.size(8.dp))
                    MenuItem("Open") { menuFor = null; io("Opening ${f.name}…") { t -> viewFile(ctx, t, full(f), f.name, Intent.ACTION_VIEW) } }
                    MenuItem("Save to phone…") { menuFor = null; saveTarget = f; saveLauncher.launch(f.name) }
                    MenuItem("Share…") { menuFor = null; io("Preparing ${f.name}…") { t -> viewFile(ctx, t, full(f), f.name, Intent.ACTION_SEND) } }
                    if (writable) {
                        MenuItem("Rename…") { menuFor = null; renaming = f }
                        MenuItem("Delete", MaterialTheme.colorScheme.error) { menuFor = null; deleting = f }
                    }
                }
            },
            confirmButton = { TextButton(onClick = { menuFor = null }) { Text("Close") } },
        )
    }
    renaming?.let { f ->
        NameDialog("Rename", f.name, onDismiss = { renaming = null }) { n ->
            renaming = null
            io("Renaming…") { t -> t.rename(full(f), "$path/$n"); withContext(Dispatchers.Main) { reload++ } }
        }
    }
    if (newFolder) {
        NameDialog("New folder", "", onDismiss = { newFolder = false }) { n ->
            newFolder = false
            io("Creating folder…") { t -> t.mkdir("$path/$n"); withContext(Dispatchers.Main) { reload++ } }
        }
    }
    deleting?.let { f ->
        AlertDialog(
            onDismissRequest = { deleting = null },
            title = { Text("Delete ${f.name}?") },
            text = { Text("This deletes it on the hub.") },
            confirmButton = {
                TextButton(onClick = {
                    deleting = null
                    io("Deleting…") { t -> t.delete(full(f)); withContext(Dispatchers.Main) { reload++ } }
                }) { Text("Delete", color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = { TextButton(onClick = { deleting = null }) { Text("Cancel") } },
        )
    }
    if (entries.isEmpty() && !loading) {
        Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
            Text("Empty folder", color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

@Composable
private fun Thumb(fullPath: String, f: HubFile, sizeDp: Int, px: Int) {
    val key = "$fullPath#$px"
    val bmp by produceState(Thumbs.cache.get(key), key) {
        if (value != null || !thumbable(f)) return@produceState
        val t = TunnelManager.tunnel ?: return@produceState
        value = withContext(Dispatchers.IO) {
            Thumbs.gate.withPermit {
                runCatching {
                    val b = t.thumb(fullPath, px)
                    BitmapFactory.decodeByteArray(b, 0, b.size)?.asImageBitmap()
                }.getOrNull()
            }
        }?.also { Thumbs.cache.put(key, it) }
    }
    Box(Modifier.size(sizeDp.dp).clip(RoundedCornerShape(6.dp)), contentAlignment = Alignment.Center) {
        val b = bmp
        if (b != null) Image(b, null, Modifier.fillMaxSize(), contentScale = ContentScale.Crop)
        else Text(icon(f), fontSize = (sizeDp * 0.55f).sp)
    }
}

@Composable
private fun Choice(label: String, value: String, options: List<Pair<String, String>>, onPick: (String) -> Unit) {
    var open by remember { mutableStateOf(false) }
    Box {
        TextButton(onClick = { open = true }) { Text("$label: ${options.first { it.first == value }.second} ▾", style = MaterialTheme.typography.labelLarge) }
        DropdownMenu(expanded = open, onDismissRequest = { open = false }) {
            options.forEach { (k, v) -> DropdownMenuItem(text = { Text(v) }, onClick = { open = false; onPick(k) }) }
        }
    }
}

@Composable
private fun Header(label: String, key: String, sort: String, asc: Boolean, modifier: Modifier, onSort: (String) -> Unit) {
    Text(
        label + if (sort == key) (if (asc) " ▲" else " ▼") else "",
        style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.SemiBold,
        modifier = modifier.clickable { onSort(key) },
    )
}

@Composable
private fun MenuItem(label: String, color: Color = Color.Unspecified, onClick: () -> Unit) {
    TextButton(onClick = onClick, modifier = Modifier.fillMaxWidth()) {
        Text(label, color = color, modifier = Modifier.fillMaxWidth())
    }
}

@Composable
private fun NameDialog(title: String, initial: String, onDismiss: () -> Unit, onOk: (String) -> Unit) {
    var name by remember { mutableStateOf(initial) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = { OutlinedTextField(name, { name = it }, singleLine = true) },
        confirmButton = { TextButton(onClick = { onOk(name.trim()) }, enabled = name.isNotBlank()) { Text("OK") } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

private fun nameAndSize(ctx: Context, uri: Uri): Pair<String, Long> {
    ctx.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE), null, null, null)?.use { c ->
        if (c.moveToFirst()) return (c.getString(0) ?: "upload") to c.getLong(1)
    }
    return "upload" to 0
}

/** Downloads to the app's private cache, then opens or shares it with another app. */
private suspend fun viewFile(ctx: Context, t: Tunnel, path: String, name: String, action: String) {
    val dir = File(ctx.cacheDir, "open").apply { mkdirs() }
    dir.listFiles()?.forEach { if (System.currentTimeMillis() - it.lastModified() > 3_600_000) it.delete() }
    val out = File(dir, name.replace(Regex("[\\\\/:*?\"<>|]"), "_"))
    t.get(path).use { r -> out.outputStream().use { r.body.copyTo(it) } }
    val uri = FileProvider.getUriForFile(ctx, "app.securdp.files", out)
    val mime = MimeTypeMap.getSingleton().getMimeTypeFromExtension(ext(name)) ?: "application/octet-stream"
    val intent = Intent(action).addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
    if (action == Intent.ACTION_SEND) intent.setType(mime).putExtra(Intent.EXTRA_STREAM, uri)
    else intent.setDataAndType(uri, mime)
    withContext(Dispatchers.Main) {
        try {
            ctx.startActivity(Intent.createChooser(intent, name).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        } catch (_: ActivityNotFoundException) {
            Toast.makeText(ctx, "No app on this phone can open $name", Toast.LENGTH_LONG).show()
        }
    }
}

// ------------------------------------------------------------------ web page

private const val MATCH = android.view.ViewGroup.LayoutParams.MATCH_PARENT

private tailrec fun Context.findActivity(): android.app.Activity? = when (this) {
    is android.app.Activity -> this
    is android.content.ContextWrapper -> baseContext.findActivity()
    else -> null
}

@SuppressLint("SetJavaScriptEnabled")
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun WebScreen(profile: Profile, service: HubService, store: ProfileStore, onClose: () -> Unit) {
    val ctx = LocalContext.current
    var ready by remember { mutableStateOf<String?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    var sslAsk by remember { mutableStateOf<SslErrorHandler?>(null) }
    var trusted by remember { mutableStateOf(false) }
    var web by remember { mutableStateOf<WebView?>(null) }
    var progress by remember { mutableStateOf(0) } // 0-100 for the page being loaded
    var localPort by remember { mutableStateOf(0) }
    var unreachable by remember { mutableStateOf<String?>(null) }
    var menu by remember { mutableStateOf(false) }
    var debugging by remember { mutableStateOf(store.pageDebugging) }
    // A page element shown fullscreen (image viewer, video), see onShowCustomView.
    var fullscreen by remember { mutableStateOf<Pair<android.view.View, WebChromeClient.CustomViewCallback>?>(null) }
    val main = remember { android.os.Handler(android.os.Looper.getMainLooper()) }
    fun toast(m: String) = main.post { Toast.makeText(ctx, m, Toast.LENGTH_LONG).show() }

    // Forward a stable local port to the service and hold the tunnel open.
    DisposableEffect(service.name) {
        var h: AutoCloseable? = null
        thread(isDaemon = true) {
            val t = TunnelManager.tunnel
            runCatching {
                val port = store.portFor(profile.name, "web:" + service.name)
                t!!.listenService(service.name, port)
                h = t.hold()
                localPort = port
                ready = "${service.scheme}://127.0.0.1:$port${service.path}"
            }.onFailure { error = it.message ?: "Couldn't open ${service.name}" }
        }
        onDispose { thread(isDaemon = true) { runCatching { h?.close() } } }
    }
    BackHandler { if (web?.canGoBack() == true) web?.goBack() else onClose() }
    // Declared after the one above so Back leaves fullscreen first.
    BackHandler(enabled = fullscreen != null) { fullscreen?.second?.onCustomViewHidden() }
    LaunchedEffect(debugging) { WebView.setWebContentsDebuggingEnabled(debugging) }

    // Fullscreen the standard way: the page's element goes over the whole
    // activity window with the system bars hidden, and comes back on exit.
    val activity = remember(ctx) { ctx.findActivity() }
    DisposableEffect(fullscreen) {
        val (view, _) = fullscreen ?: return@DisposableEffect onDispose {}
        val decor = activity?.window?.decorView as? android.widget.FrameLayout
        val bars = activity?.window?.let { androidx.core.view.WindowCompat.getInsetsController(it, it.decorView) }
        decor?.addView(view, android.widget.FrameLayout.LayoutParams(MATCH, MATCH))
        bars?.systemBarsBehavior = androidx.core.view.WindowInsetsControllerCompat.BEHAVIOR_SHOW_TRANSIENT_BARS_BY_SWIPE
        bars?.hide(androidx.core.view.WindowInsetsCompat.Type.systemBars())
        onDispose {
            decor?.removeView(view)
            bars?.show(androidx.core.view.WindowInsetsCompat.Type.systemBars())
        }
    }
    // Leaving the page while fullscreen still tells the page it ended.
    DisposableEffect(Unit) { onDispose { fullscreen?.second?.onCustomViewHidden() } }

    /** Decides where a navigation goes; true = handled here (don't load it in the view). */
    fun route(view: WebView, url: String): Boolean = when (val r = routeLink(url, localPort, service.target)) {
        LinkRoute.Tunnel, LinkRoute.Other -> false
        is LinkRoute.Rewrite -> { view.loadUrl(r.url); true }
        is LinkRoute.Unreachable -> { unreachable = r.host; true }
        LinkRoute.Internet -> { openInBrowser(ctx, url); true }
    }

    Scaffold(topBar = {
        TopAppBar(
            title = { Text(service.name, fontWeight = FontWeight.SemiBold) },
            navigationIcon = { TextButton(onClick = onClose) { Text("‹ Back") } },
            actions = {
                if (progress < 100 && ready != null) TextButton(onClick = { web?.stopLoading(); progress = 100 }) { Text("✕") }
                else TextButton(onClick = { web?.reload() }) { Text("↻") }
                TextButton(onClick = { TunnelManager.openExternal(ctx, profile, service, store) }) { Text("Chrome ↗") }
                Box {
                    TextButton(onClick = { menu = true }) { Text("⋮") }
                    DropdownMenu(expanded = menu, onDismissRequest = { menu = false }) {
                        DropdownMenuItem(
                            text = { Text("Page debugging (USB)") },
                            leadingIcon = { Checkbox(checked = debugging, onCheckedChange = null) },
                            onClick = {
                                debugging = !debugging
                                store.pageDebugging = debugging
                                menu = false
                                if (debugging) toast("Connect the phone by USB and open chrome://inspect on the PC. Reopen the page if it isn't listed.")
                            },
                        )
                    }
                }
            },
        )
    }) { pad ->
        Box(Modifier.fillMaxSize().padding(pad)) {
            val url = ready
            // Loading bar across the top (home devices like routers can be slow).
            if (url != null && error == null && progress < 100) {
                if (progress <= 5) LinearProgressIndicator(Modifier.fillMaxWidth().zIndex(1f))
                else LinearProgressIndicator(progress = { progress / 100f }, modifier = Modifier.fillMaxWidth().zIndex(1f))
            }
            when {
                error != null -> Text(error!!, Modifier.padding(16.dp), color = MaterialTheme.colorScheme.error)
                url == null -> LinearProgressIndicator(Modifier.fillMaxWidth())
                else -> AndroidView(modifier = Modifier.fillMaxSize(), factory = { c ->
                    WebView(c).apply {
                        // AndroidView otherwise lays the WebView out as wrap_content, and pages
                        // then see a 0px viewport height (100vh/dvh = 0).
                        layoutParams = android.view.ViewGroup.LayoutParams(MATCH, MATCH)
                        settings.javaScriptEnabled = true
                        settings.domStorageEnabled = true
                        settings.loadWithOverviewMode = true
                        settings.useWideViewPort = true
                        settings.builtInZoomControls = true
                        settings.displayZoomControls = false
                        // Galleries often open full-size images in a new tab/window.
                        settings.setSupportMultipleWindows(true)
                        settings.javaScriptCanOpenWindowsAutomatically = true
                        val mainView = this
                        webChromeClient = object : WebChromeClient() {
                            override fun onProgressChanged(view: WebView, newProgress: Int) { progress = newProgress }

                            // Element.requestFullscreen() (image viewers, videos) only works if the app shows the view.
                            override fun onShowCustomView(view: android.view.View, callback: CustomViewCallback) {
                                if (fullscreen != null) callback.onCustomViewHidden() else fullscreen = view to callback
                            }

                            override fun onHideCustomView() { fullscreen = null }

                            // Page errors go to logcat (adb logcat -s SecuRDPWeb) for troubleshooting.
                            override fun onConsoleMessage(msg: android.webkit.ConsoleMessage): Boolean {
                                android.util.Log.d("SecuRDPWeb", "${msg.messageLevel()} ${msg.sourceId()}:${msg.lineNumber()} ${msg.message()}")
                                return true
                            }

                            // A "new window" is loaded in this view instead (Back returns to the gallery).
                            override fun onCreateWindow(view: WebView, isDialog: Boolean, isUserGesture: Boolean, resultMsg: android.os.Message): Boolean {
                                val popup = WebView(view.context)
                                popup.webViewClient = object : WebViewClient() {
                                    override fun shouldOverrideUrlLoading(v: WebView, req: android.webkit.WebResourceRequest): Boolean {
                                        val u = req.url.toString()
                                        if (!route(mainView, u)) mainView.loadUrl(u)
                                        v.destroy()
                                        return true
                                    }

                                    override fun onPageStarted(v: WebView, u: String?, favicon: android.graphics.Bitmap?) {
                                        if (u != null && u != "about:blank") {
                                            v.stopLoading()
                                            if (!route(mainView, u)) mainView.loadUrl(u)
                                            v.destroy()
                                        }
                                    }
                                }
                                (resultMsg.obj as WebView.WebViewTransport).webView = popup
                                resultMsg.sendToTarget()
                                return true
                            }
                        }
                        // Downloads ("save", "original image") go to the phone's Downloads/SecuRDP.
                        setDownloadListener { dlUrl, userAgent, disposition, mime, _ ->
                            val target = when (val r = routeLink(dlUrl, localPort, service.target)) {
                                is LinkRoute.Rewrite -> r.url
                                LinkRoute.Tunnel -> dlUrl
                                else -> null
                            }
                            if (target == null) {
                                toast("This download needs the browser - tap Chrome ↗ at the top and try it there.")
                            } else {
                                toast("Downloading…")
                                thread(isDaemon = true) {
                                    runCatching { downloadThroughTunnel(ctx, target, userAgent, disposition, mime, trusted) }
                                        .onSuccess { (name, uri) ->
                                            toast("Saved $name to Downloads/SecuRDP")
                                            main.post { openDownloaded(ctx, uri, name) }
                                        }
                                        .onFailure { toast(it.message ?: "Download failed") }
                                }
                            }
                        }
                        webViewClient = object : WebViewClient() {
                            override fun onPageStarted(view: WebView, url: String?, favicon: android.graphics.Bitmap?) { progress = 0 }
                            override fun onPageFinished(view: WebView, url: String?) { progress = 100 }

                            override fun shouldOverrideUrlLoading(view: WebView, req: android.webkit.WebResourceRequest): Boolean =
                                route(view, req.url.toString())

                            // Images/scripts the page loads from its real home address come through the tunnel too.
                            override fun shouldInterceptRequest(view: WebView, req: android.webkit.WebResourceRequest): android.webkit.WebResourceResponse? {
                                if (!req.method.equals("GET", true)) return null
                                val r = routeLink(req.url.toString(), localPort, service.target)
                                return if (r is LinkRoute.Rewrite) tunnelResponse(r.url, req.requestHeaders, trusted) else null
                            }

                            // Home devices often use self-signed certificates: ask once per page visit.
                            @SuppressLint("WebViewClientOnReceivedSslError")
                            override fun onReceivedSslError(view: WebView, handler: SslErrorHandler, err: SslError) {
                                if (trusted) handler.proceed() else sslAsk = handler
                            }
                        }
                        loadUrl(url)
                        web = this
                    }
                })
            }
        }
    }
    unreachable?.let { host ->
        AlertDialog(
            onDismissRequest = { unreachable = null },
            title = { Text("Can't open that link") },
            text = {
                Text(
                    "It points to $host on your home network, which isn't part of this web page's tunnel. " +
                        "To reach it, add that address as its own web page on the hub (Files & Web tab).",
                )
            },
            confirmButton = { TextButton(onClick = { unreachable = null }) { Text("OK") } },
        )
    }
    sslAsk?.let { h ->
        AlertDialog(
            onDismissRequest = { h.cancel(); sslAsk = null },
            title = { Text("Untrusted certificate") },
            text = { Text("${service.name} uses a certificate this phone doesn't recognise. That's normal for routers and other home devices with a self-signed certificate. Continue?") },
            confirmButton = { TextButton(onClick = { trusted = true; h.proceed(); sslAsk = null }) { Text("Continue") } },
            dismissButton = { TextButton(onClick = { h.cancel(); sslAsk = null }) { Text("Cancel") } },
        )
    }
}
