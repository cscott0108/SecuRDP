package app.securdp

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.Uri
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlin.concurrent.thread

sealed interface TunnelState {
    data object Idle : TunnelState
    data class Connecting(val profile: Profile) : TunnelState
    /** [profile].localPort is the port actually in use (per hub PC). */
    data class Connected(val profile: Profile, val active: Int, val computer: String? = null) : TunnelState
    data class NeedsTrust(val profile: Profile, val fingerprint: String) : TunnelState
    /** Logged in to a hub with several PCs: the user picks one. */
    data class NeedsChoice(val profile: Profile, val computers: List<HubComputer>) : TunnelState
    data class Failed(val message: String) : TunnelState
}

/** Process-wide tunnel state shared by the UI and the service. */
object TunnelManager {
    private val _state = MutableStateFlow<TunnelState>(TunnelState.Idle)
    val state: StateFlow<TunnelState> = _state

    // Credentials stay in memory only, never in an Intent or on disk.
    internal var pending: Triple<Profile, String, String>? = null
    internal var tunnel: Tunnel? = null

    internal fun set(s: TunnelState) { _state.value = s }

    fun connect(context: Context, profile: Profile, password: String, code: String) {
        if (tunnel != null) return
        pending = Triple(profile, password, code)
        set(TunnelState.Connecting(profile))
        val intent = Intent(context, TunnelService::class.java).setAction(TunnelService.ACTION_START)
        context.startForegroundService(intent)
    }

    fun disconnect() {
        tunnel?.close("Disconnected")
    }

    /** Answers the hub picker; null computer cancels (and logs out). */
    fun choose(context: Context, computer: String?, remember: Boolean) {
        context.startService(
            Intent(context, TunnelService::class.java).setAction(TunnelService.ACTION_CHOOSE)
                .putExtra("computer", computer).putExtra("remember", remember),
        )
    }

    fun clearMessage() {
        if (_state.value is TunnelState.Failed || _state.value is TunnelState.NeedsTrust) set(TunnelState.Idle)
    }
}

class TunnelService : Service() {
    companion object {
        const val ACTION_START = "app.securdp.START"
        const val ACTION_STOP = "app.securdp.STOP"
        const val ACTION_CHOOSE = "app.securdp.CHOOSE"
        private const val CHANNEL = "tunnel"
        private const val NOTIF_ID = 1
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                TunnelManager.disconnect()
                stopSelfSafely()
            }
            ACTION_START -> start()
            ACTION_CHOOSE -> choose(intent.getStringExtra("computer"), intent.getBooleanExtra("remember", false))
        }
        return START_NOT_STICKY
    }

    // The profile as forwarded (localPort = the port in use) and its hub PC.
    @Volatile private var current: Profile? = null
    @Volatile private var computer: String? = null

    private fun label(p: Profile) = p.name + (computer?.let { " → $it" } ?: "")

    private fun start() {
        val (profile, password, code) = TunnelManager.pending ?: return stopSelfSafely()
        TunnelManager.pending = null
        current = null
        computer = null
        goForeground(notification("Connecting to ${profile.name}…", profile))

        thread(name = "securdp-connect") {
            val t = Tunnel(
                host = profile.host, port = profile.port, username = profile.username,
                pinnedFingerprint = profile.hostFingerprint, localPort = profile.localPort,
                listener = object : Tunnel.Listener {
                    override fun onActiveChanged(active: Int) {
                        val p = current ?: profile
                        TunnelManager.set(TunnelState.Connected(p, active, computer))
                        val what = if (active > 0) "Remote Desktop connected" else "Tunnel open - waiting for Remote Desktop"
                        updateNotification(notification("$what · ${label(p)}", p))
                    }

                    override fun onClosed(reason: String) {
                        TunnelManager.tunnel = null
                        current = null
                        TunnelManager.set(if (reason == "Disconnected") TunnelState.Idle else TunnelState.Failed(reason))
                        stopSelfSafely()
                    }
                },
            )
            try {
                t.connect(password, code)
                TunnelManager.tunnel = t
                val list = t.computers()
                if (list.size > 1) {
                    val saved = list.firstOrNull { it.name == profile.computer }
                    if (saved != null) {
                        forwardTo(t, profile, saved.name)
                    } else {
                        TunnelManager.set(TunnelState.NeedsChoice(profile, list))
                        updateNotification(notification("Choose a computer · ${profile.name}", profile))
                    }
                } else {
                    forwardTo(t, profile, null)
                }
            } catch (e: UnknownHostException) {
                TunnelManager.set(TunnelState.NeedsTrust(profile, e.fingerprint))
                stopSelfSafely()
            } catch (e: Exception) {
                TunnelManager.set(TunnelState.Failed(e.message ?: e.toString()))
                stopSelfSafely()
            }
        }
    }

    /** Starts forwarding to [name] (null = the login's computer) on its own local port. */
    private fun forwardTo(t: Tunnel, profile: Profile, name: String?) {
        val port = if (name == null) profile.localPort else ProfileStore(this).portFor(profile.name, name)
        t.listen(name, port)
        val p = profile.copy(localPort = port)
        current = p
        computer = name
        TunnelManager.set(TunnelState.Connected(p, 0, name))
        updateNotification(notification("Tunnel open - waiting for Remote Desktop · ${label(p)}", p))
        // The visible activity opens Remote Desktop (Android blocks activity starts from services).
    }

    private fun choose(name: String?, remember: Boolean) {
        val t = TunnelManager.tunnel ?: return
        val st = TunnelManager.state.value as? TunnelState.NeedsChoice ?: return
        if (name == null) {
            t.close("Disconnected")
            return
        }
        if (remember) ProfileStore(this).setComputer(st.profile.name, name)
        thread(name = "securdp-choose") {
            try {
                forwardTo(t, st.profile, name)
            } catch (e: Exception) {
                TunnelManager.set(TunnelState.Failed(e.message ?: e.toString()))
                t.close(e.message ?: "Failed")
            }
        }
    }

    private fun stopSelfSafely() {
        ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun goForeground(n: Notification) {
        val type = if (Build.VERSION.SDK_INT >= 34) ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE else 0
        ServiceCompat.startForeground(this, NOTIF_ID, n, type)
    }

    private fun updateNotification(n: Notification) {
        getSystemService(NotificationManager::class.java).notify(NOTIF_ID, n)
    }

    private fun notification(text: String, profile: Profile): Notification {
        val nm = getSystemService(NotificationManager::class.java)
        if (nm.getNotificationChannel(CHANNEL) == null) {
            nm.createNotificationChannel(NotificationChannel(CHANNEL, "Active tunnel", NotificationManager.IMPORTANCE_LOW))
        }
        val open = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
            PendingIntent.FLAG_IMMUTABLE,
        )
        val stop = PendingIntent.getService(
            this, 1, Intent(this, TunnelService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_IMMUTABLE,
        )
        return NotificationCompat.Builder(this, CHANNEL)
            .setSmallIcon(R.drawable.ic_stat_lock)
            .setContentTitle("SecuRDP")
            .setContentText(text)
            .setSubText("127.0.0.1:${profile.localPort}")
            .setOngoing(true)
            .setContentIntent(open)
            .addAction(0, "Disconnect", stop)
            .setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE)
            .build()
    }
}

/**
 * Opens Microsoft's Remote Desktop client at the tunnel. Tries the rdp:// URI
 * (connects directly), then just launches the app, then the Play Store.
 */
fun openRemoteDesktop(context: Context, profile: Profile) {
    val newTask = Intent.FLAG_ACTIVITY_NEW_TASK
    var uri = "rdp://full%20address=s:127.0.0.1:${profile.localPort}"
    if (profile.rdpUsername.isNotEmpty()) uri += "&username=s:" + Uri.encode(profile.rdpUsername)
    try {
        context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(uri)).addFlags(newTask))
        return
    } catch (_: ActivityNotFoundException) {
    }
    for (pkg in listOf("com.microsoft.rdc.androidx", "com.microsoft.rdc.android")) {
        context.packageManager.getLaunchIntentForPackage(pkg)?.let {
            context.startActivity(it.addFlags(newTask))
            return
        }
    }
    try {
        context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("market://details?id=com.microsoft.rdc.androidx")).addFlags(newTask))
    } catch (_: ActivityNotFoundException) {
    }
}
