package app.securdp

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/** App-link status for the UI: key alias -> "Ready" / "Connected" / an error. */
object LinkManager {
    private val _status = MutableStateFlow<Map<String, String>>(emptyMap())
    val status: StateFlow<Map<String, String>> = _status

    internal fun setStatus(alias: String, s: String?) {
        _status.value = if (s == null) _status.value - alias else _status.value + (alias to s)
    }

    /** Starts, updates or stops the background service to match the saved links. */
    fun refresh(context: Context) {
        val intent = Intent(context, LinkService::class.java).setAction(LinkService.ACTION_REFRESH)
        if (ProfileStore(context).links().any { it.enabled }) context.startForegroundService(intent)
        else context.startService(intent) // lets a running service stop itself
    }
}

/**
 * Keeps the enabled app links' loopback ports listening. Android only keeps a
 * listening port alive in a foreground service; while no app uses a link the
 * service holds no connection, so it costs next to nothing.
 */
class LinkService : Service() {
    companion object {
        const val ACTION_REFRESH = "app.securdp.LINKS"
        private const val CHANNEL = "links"
        private const val NOTIF_ID = 2
    }

    private val running = mutableMapOf<LinkConfig, AppLink>()

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val store = ProfileStore(this)
        val wanted = store.links().filter { it.enabled }
        if (wanted.isEmpty()) {
            stopAll()
            ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
            stopSelf()
            return START_NOT_STICKY
        }
        val type = if (Build.VERSION.SDK_INT >= 34) ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE else 0
        ServiceCompat.startForeground(this, NOTIF_ID, notification(wanted), type)

        // Stop links that were removed or changed, then start the new ones.
        (running.keys - wanted.toSet()).forEach { c ->
            running.remove(c)?.stop()
            LinkManager.setStatus(c.keyAlias, null)
        }
        val profiles = store.load()
        for (c in wanted) {
            if (c in running) continue
            val p = profiles.firstOrNull { it.name == c.profile }
            val id = DeviceKeys.identity(c.keyAlias)
            if (p == null || id == null) {
                LinkManager.setStatus(c.keyAlias, if (p == null) "Its saved computer was deleted" else "Its key is missing - pair again")
                continue
            }
            val link = AppLink(
                host = p.host, port = p.port, username = p.username, pinnedFingerprint = p.hostFingerprint,
                service = c.service, localPort = c.localPort, identity = id,
                onStatus = { LinkManager.setStatus(c.keyAlias, it) },
            )
            try {
                link.start()
                running[c] = link
            } catch (e: Exception) {
                LinkManager.setStatus(c.keyAlias, "Port ${c.localPort} is in use by another app")
            }
        }
        // Restarted by Android if it has to kill the process.
        return START_STICKY
    }

    private fun stopAll() {
        running.forEach { (c, l) -> l.stop(); LinkManager.setStatus(c.keyAlias, null) }
        running.clear()
    }

    override fun onDestroy() {
        stopAll()
        super.onDestroy()
    }

    private fun notification(links: List<LinkConfig>): Notification {
        val nm = getSystemService(NotificationManager::class.java)
        if (nm.getNotificationChannel(CHANNEL) == null) {
            nm.createNotificationChannel(NotificationChannel(CHANNEL, "App links", NotificationManager.IMPORTANCE_MIN))
        }
        val open = PendingIntent.getActivity(
            this, 2, Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
            PendingIntent.FLAG_IMMUTABLE,
        )
        val what = links.joinToString(", ") { "${it.service} → 127.0.0.1:${it.localPort}" }
        return NotificationCompat.Builder(this, CHANNEL)
            .setSmallIcon(R.drawable.ic_stat_lock)
            .setContentTitle("App link ready")
            .setContentText(what)
            .setOngoing(true)
            .setContentIntent(open)
            .build()
    }
}

/** Restarts the app links after the phone reboots or the app is updated. */
class LinkBootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == Intent.ACTION_BOOT_COMPLETED || intent.action == Intent.ACTION_MY_PACKAGE_REPLACED) {
            if (ProfileStore(context).links().any { it.enabled }) LinkManager.refresh(context)
        }
    }
}
