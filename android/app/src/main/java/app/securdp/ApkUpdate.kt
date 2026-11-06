package app.securdp

import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInstaller
import android.os.Build
import android.widget.Toast
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import java.io.File
import kotlin.concurrent.thread

// Updating the Android app from the hub: a 1.9+ hub bundles the app and says
// which version it has. The app downloads it through the tunnel (size +
// SHA-256 checked) and hands it to Android's PackageInstaller, which asks you
// to confirm (and, the first time, to allow SecuRDP to install apps).
// Android only accepts it if it is signed with the same key as this app.

/** This app's versionCode. */
fun installedVersionCode(ctx: Context): Long {
    val info = ctx.packageManager.getPackageInfo(ctx.packageName, 0)
    return if (Build.VERSION.SDK_INT >= 28) info.longVersionCode else @Suppress("DEPRECATION") info.versionCode.toLong()
}

object ApkUpdater {
    /** Downloads the hub's app and starts installing it. Blocking; call off the main thread. */
    fun downloadAndInstall(ctx: Context, progress: (Long, Long) -> Unit) {
        val t = TunnelManager.tunnel ?: throw Exception("Not connected to the hub")
        val file = File(ctx.cacheDir, "update/SecuRDP.apk").apply { parentFile?.mkdirs() }
        file.outputStream().use { t.downloadApk(it, progress) }

        val installer = ctx.packageManager.packageInstaller
        val params = PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL)
            .apply { setAppPackageName(ctx.packageName) }
        val id = installer.createSession(params)
        installer.openSession(id).use { s ->
            s.openWrite("SecuRDP.apk", 0, file.length()).use { out ->
                file.inputStream().use { it.copyTo(out) }
                s.fsync(out)
            }
            // Mutable: the installer adds the status (and confirm intent) to it.
            val flags = PendingIntent.FLAG_UPDATE_CURRENT or (if (Build.VERSION.SDK_INT >= 31) PendingIntent.FLAG_MUTABLE else 0)
            val result = PendingIntent.getBroadcast(ctx, id, Intent(ctx, InstallResultReceiver::class.java), flags)
            s.commit(result.intentSender)
        }
        file.delete()
    }
}

/** Gets PackageInstaller's answer: shows the confirmation, or reports a failure. */
class InstallResultReceiver : BroadcastReceiver() {
    override fun onReceive(ctx: Context, intent: Intent) {
        when (val status = intent.getIntExtra(PackageInstaller.EXTRA_STATUS, PackageInstaller.STATUS_FAILURE)) {
            PackageInstaller.STATUS_PENDING_USER_ACTION -> {
                val confirm = if (Build.VERSION.SDK_INT >= 33) intent.getParcelableExtra(Intent.EXTRA_INTENT, Intent::class.java)
                else @Suppress("DEPRECATION") intent.getParcelableExtra(Intent.EXTRA_INTENT)
                confirm?.let { ctx.startActivity(it.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)) }
            }
            PackageInstaller.STATUS_SUCCESS -> {}
            else -> {
                val msg = intent.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE) ?: "status $status"
                val hint = if (status == PackageInstaller.STATUS_FAILURE_CONFLICT || status == PackageInstaller.STATUS_FAILURE_INCOMPATIBLE)
                    " (is it signed with the same key as this app?)" else ""
                Toast.makeText(ctx, "Update not installed: $msg$hint", Toast.LENGTH_LONG).show()
            }
        }
    }
}

/** "SecuRDP x.y is available from this hub" with Download & install, if the hub's app is newer. */
@Composable
fun ApkUpdateCard(info: HubInfo) {
    val ctx = LocalContext.current
    val current = remember { runCatching { installedVersionCode(ctx) }.getOrDefault(Long.MAX_VALUE) }
    if (info.apkCode <= current) return
    var progress by remember { mutableStateOf<Float?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    val main = remember { android.os.Handler(android.os.Looper.getMainLooper()) }
    Card(
        Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("SecuRDP ${info.apkName} is available from this hub", fontWeight = FontWeight.SemiBold)
            Text(
                "Downloads through this connection, then Android asks you to confirm. " +
                    "Installing restarts the app and closes the connection.",
                style = MaterialTheme.typography.bodySmall,
            )
            progress?.let { LinearProgressIndicator(progress = { it }, modifier = Modifier.fillMaxWidth()) }
            error?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
            Button(enabled = progress == null, onClick = {
                progress = 0f
                error = null
                thread(name = "securdp-apk") {
                    try {
                        ApkUpdater.downloadAndInstall(ctx) { done, total -> main.post { progress = done.toFloat() / total } }
                        main.post { progress = null }
                    } catch (e: Exception) {
                        main.post { progress = null; error = e.message ?: "Download failed" }
                    }
                }
            }) { Text(if (progress == null) "Download & install" else "Downloading…") }
        }
    }
}
