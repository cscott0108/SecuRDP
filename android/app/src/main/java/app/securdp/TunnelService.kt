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
    /** [profile].localPort is the port actually in use (per hub PC). [info] is set for hub logins. */
    data class Connected(
        val profile: Profile, val active: Int, val computer: String? = null, val info: HubInfo? = null,
    ) : TunnelState
    data class NeedsTrust(val profile: Profile, val fingerprint: String) : TunnelState
    /** Logged in to a hub (several PCs, or files / web pages): show the hub screen. */
    data class Hub(val profile: Profile, val info: HubInfo) : TunnelState
    data class Failed(val message: String) : TunnelState
}

/** How the current tunnel is logged in: [home] = Local; [lost] = dropped, waiting to reconnect. */
data class LoginMode(val home: Boolean = false, val lost: Boolean = false)

/** Process-wide tunnel state shared by the UI and the service. */
object TunnelManager {
    private val _state = MutableStateFlow<TunnelState>(TunnelState.Idle)
    val state: StateFlow<TunnelState> = _state
    private val _login = MutableStateFlow(LoginMode())
    val login: StateFlow<LoginMode> = _login
    internal fun setLogin(m: LoginMode) { _login.value = m }

    /**
     * Moves the tunnel to a password + code login through the profile's public
     * address, keeping Remote Desktop, files and pages open: leaves a Local
     * login, or reconnects one that dropped. [done] gets null or the error.
     */
    fun switchRemote(password: String, code: String, done: (String?) -> Unit) {
        val t = tunnel ?: return done("Not connected")
        thread(name = "securdp-switch") {
            val err = try {
                t.switchRemote(password, code)
                null
            } catch (_: LoginFailedException) {
                "Login failed - check your password and code (too many failures block your IP for a while)."
            } catch (e: Exception) {
                e.message ?: e.toString()
            }
            android.os.Handler(android.os.Looper.getMainLooper()).post { done(err) }
        }
    }

    // Credentials stay in memory only, never in an Intent or on disk.
    internal var pending: Triple<Profile, String, String>? = null
    internal var pendingHome = false // the Local button: log in with the home key
    internal var tunnel: Tunnel? = null

    internal fun set(s: TunnelState) { _state.value = s }

    fun connect(context: Context, profile: Profile, password: String, code: String) {
        if (tunnel != null) return
        pending = Triple(profile, password, code)
        pendingHome = false
        set(TunnelState.Connecting(profile))
        val intent = Intent(context, TunnelService::class.java).setAction(TunnelService.ACTION_START)
        context.startForegroundService(intent)
    }

    /** The Local button: logs in with this phone's trusted home key (home network only). */
    fun connectHome(context: Context, profile: Profile) {
        if (tunnel != null) return
        pending = Triple(profile, "", "")
        pendingHome = true
        set(TunnelState.Connecting(profile))
        context.startForegroundService(Intent(context, TunnelService::class.java).setAction(TunnelService.ACTION_START))
    }

    fun disconnect() {
        tunnel?.close("Disconnected")
    }

    // Web pages opened in the phone's browser: each holds the tunnel open
    // until stopped (the browser can't tell us when its tab is closed).
    private val external = mutableMapOf<String, AutoCloseable>()
    private val _externalPages = MutableStateFlow<Set<String>>(emptySet())
    val externalPages: StateFlow<Set<String>> = _externalPages

    /** Opens a hub web page in Chrome (or the default browser) through the tunnel. */
    fun openExternal(context: Context, profile: Profile, service: HubService, store: ProfileStore) {
        val t = tunnel ?: return
        thread(name = "securdp-external") {
            try {
                val port = store.portFor(profile.name, "web:" + service.name)
                t.listenService(service.name, port)
                synchronized(external) {
                    if (service.name !in external) external[service.name] = t.hold()
                    _externalPages.value = external.keys.toSet()
                }
                openInBrowser(context, "${service.scheme}://127.0.0.1:$port${service.path}")
            } catch (e: Exception) {
                android.os.Handler(android.os.Looper.getMainLooper()).post {
                    android.widget.Toast.makeText(context, e.message ?: "Couldn't open ${service.name}", android.widget.Toast.LENGTH_LONG).show()
                }
            }
        }
    }

    fun stopExternal(name: String) {
        val h = synchronized(external) {
            external.remove(name).also { _externalPages.value = external.keys.toSet() }
        }
        thread(isDaemon = true) { runCatching { h?.close() } }
    }

    internal fun clearExternal() = synchronized(external) {
        external.clear()
        _externalPages.value = emptySet()
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

    // The profile as forwarded (localPort = the port in use), its hub PC, and the hub's offer.
    @Volatile private var current: Profile? = null
    @Volatile private var computer: String? = null
    @Volatile private var hubInfo: HubInfo? = null

    private fun label(p: Profile) = p.name + (computer?.let { " → $it" } ?: "")

    private fun start() {
        val (profile, password, code) = TunnelManager.pending ?: return stopSelfSafely()
        val home = TunnelManager.pendingHome
        TunnelManager.pending = null
        TunnelManager.pendingHome = false
        // Local logins go straight to the hub's home address when one is saved.
        val (host, port) = if (home) homeAddress(profile) else profile.host to profile.port
        current = null
        computer = null
        hubInfo = null
        goForeground(notification("Connecting to ${profile.name}…", profile))

        thread(name = "securdp-connect") {
            val t = Tunnel(
                host = host, port = port, username = profile.username,
                pinnedFingerprint = profile.hostFingerprint, localPort = profile.localPort,
                remoteHost = profile.host, remotePort = profile.port,
                listener = object : Tunnel.Listener {
                    override fun onLoginChanged(home: Boolean, lost: Boolean) {
                        TunnelManager.setLogin(LoginMode(home, lost))
                        val p = current ?: profile
                        updateNotification(notification(
                            when {
                                lost && home -> "Connection lost - reconnects at home, or log in to continue remotely · ${label(p)}"
                                lost -> "Connection lost - open SecuRDP to reconnect · ${label(p)}"
                                home -> "Connected locally · ${label(p)}"
                                else -> "Connected · ${label(p)}"
                            },
                            p,
                        ))
                    }

                    override fun onActiveChanged(active: Int) {
                        val p = current ?: profile
                        TunnelManager.set(TunnelState.Connected(p, active, computer, hubInfo))
                        val what = if (active > 0) "Remote Desktop connected" else "Tunnel open - waiting for Remote Desktop"
                        updateNotification(notification("$what · ${label(p)}", p))
                    }

                    override fun onClosed(reason: String) {
                        TunnelManager.tunnel = null
                        TunnelManager.setLogin(LoginMode())
                        TunnelManager.clearExternal()
                        current = null
                        TunnelManager.set(if (reason == "Disconnected") TunnelState.Idle else TunnelState.Failed(reason))
                        stopSelfSafely()
                    }
                },
            )
            try {
                if (home) {
                    val id = DeviceKeys.identity(profile.homeKeyAlias)
                        ?: throw Exception("This phone's home key is missing - connect with your password and code, then trust it again.")
                    t.connectHome(id)
                } else {
                    t.connect(password, code)
                }
                TunnelManager.tunnel = t
                TunnelManager.setLogin(LoginMode(home = home))
                val info = t.info()
                val saved = info.computers.firstOrNull { it.name == profile.computer && profile.computer.isNotEmpty() }
                when {
                    saved != null -> forwardTo(t, profile, saved.name)
                    info.computers.size > 1 || info.folders.isNotEmpty() || info.services.isNotEmpty() -> {
                        hubInfo = info
                        TunnelManager.set(TunnelState.Hub(profile, info))
                        updateNotification(notification("Connected to the hub · ${profile.name}", profile))
                    }
                    else -> forwardTo(t, profile, null)
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
        TunnelManager.set(TunnelState.Connected(p, 0, name, hubInfo))
        updateNotification(notification("Tunnel open - waiting for Remote Desktop · ${label(p)}", p))
        // The visible activity opens Remote Desktop (Android blocks activity starts from services).
    }

    private fun choose(name: String?, remember: Boolean) {
        val t = TunnelManager.tunnel ?: return
        val profile = when (val st = TunnelManager.state.value) {
            is TunnelState.Hub -> st.profile
            is TunnelState.Connected -> st.profile
            else -> return
        }
        if (name == null) {
            t.close("Disconnected")
            return
        }
        if (remember) ProfileStore(this).setComputer(profile.name, name)
        thread(name = "securdp-choose") {
            try {
                forwardTo(t, profile, name)
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

/** Opens a URL in Chrome if installed, otherwise the default browser. */
fun openInBrowser(context: Context, url: String) {
    val view = Intent(Intent.ACTION_VIEW, Uri.parse(url)).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    try {
        context.startActivity(Intent(view).setPackage("com.android.chrome"))
    } catch (_: ActivityNotFoundException) {
        try {
            context.startActivity(view)
        } catch (_: ActivityNotFoundException) {
        }
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

/** The hub's home address for Local logins: [Profile.homeHost] (host or host:port), else the usual address. */
fun homeAddress(p: Profile): Pair<String, Int> {
    val h = p.homeHost.trim()
    if (h.isEmpty()) return p.host to p.port
    val port = h.substringAfterLast(':', "").toIntOrNull()
    return if (port != null && h.count { it == ':' } == 1) h.substringBeforeLast(':') to port else h to p.port
}
