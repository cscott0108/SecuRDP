package app.securdp

import com.jcraft.jsch.ChannelDirectTCPIP
import com.jcraft.jsch.HostKey
import com.jcraft.jsch.HostKeyRepository
import com.jcraft.jsch.JSch
import com.jcraft.jsch.JSchException
import com.jcraft.jsch.Session
import com.jcraft.jsch.UIKeyboardInteractive
import com.jcraft.jsch.UserInfo
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.security.MessageDigest
import java.util.Base64
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread

/** First connection: the user must confirm the server fingerprint before it is pinned. */
class UnknownHostException(val fingerprint: String) :
    Exception("First connection to this server - verify fingerprint $fingerprint")

/** The server key no longer matches the pinned one: reinstall or interception. */
class HostChangedException(val want: String, val got: String) :
    Exception("SERVER IDENTITY CHANGED! Expected $want but got $got. If you did not reinstall SecuRDP on that PC, do NOT connect.")

class LoginFailedException :
    Exception("Login failed - check username, password and authenticator code. Too many failures block your IP for a while.")

/** One computer from a hub's list. */
data class HubComputer(val name: String, val online: Boolean, val isDefault: Boolean)

/** Parses the hub's list: one "name online(0/1) default(0/1)" per line. */
fun parseComputers(text: String): List<HubComputer> =
    text.lines().mapNotNull { line ->
        val f = line.trim().split(Regex("\\s+"))
        if (f.size == 3) HubComputer(f[0], f[1] == "1", f[2] == "1") else null
    }

/** SHA256 fingerprint in the same format as OpenSSH and the Windows app. */
fun fingerprint(keyBlob: ByteArray): String =
    "SHA256:" + Base64.getEncoder().withoutPadding()
        .encodeToString(MessageDigest.getInstance("SHA-256").digest(keyBlob))

/** Accepts only the pinned key; remembers what the server presented. */
private class PinnedHostKey(private val pinned: String) : HostKeyRepository {
    @Volatile var seen: String? = null

    override fun check(host: String?, key: ByteArray): Int {
        val fp = fingerprint(key)
        seen = fp
        return when {
            pinned.isEmpty() -> HostKeyRepository.NOT_INCLUDED
            fp == pinned -> HostKeyRepository.OK
            else -> HostKeyRepository.CHANGED
        }
    }

    override fun add(hostkey: HostKey?, ui: UserInfo?) {}
    override fun remove(host: String?, type: String?) {}
    override fun remove(host: String?, type: String?, key: ByteArray?) {}
    override fun getKnownHostsRepositoryID() = "securdp-pinned"
    // JSch iterates these after a successful check, so return empty, not null.
    override fun getHostKey(): Array<HostKey> = emptyArray()
    override fun getHostKey(host: String?, type: String?): Array<HostKey> = emptyArray()
}

/** Answers the server's "Password:" / "Authenticator code:" prompt exactly once. */
private class Answers(private val password: String, private val code: String) :
    UserInfo, UIKeyboardInteractive {
    private var asked = false

    override fun promptKeyboardInteractive(
        destination: String?, name: String?, instruction: String?,
        prompt: Array<String>, echo: BooleanArray,
    ): Array<String>? {
        // A second round means the first answers were rejected: cancel rather
        // than resend them and rack up failures towards an IP ban.
        if (asked) return null
        asked = true
        return prompt.map {
            val q = it.lowercase()
            when {
                "password" in q -> password
                "code" in q || "verification" in q -> code
                else -> ""
            }
        }.toTypedArray()
    }

    override fun getPassphrase(): String? = null
    override fun getPassword(): String? = null
    override fun promptPassword(message: String?) = false
    override fun promptPassphrase(message: String?) = false
    override fun promptYesNo(message: String?) = false
    override fun showMessage(message: String?) {}
}

/**
 * An SSH connection to a SecuRDP gate plus a loopback listener whose
 * connections are forwarded to the server's Remote Desktop port.
 *
 * Mirrors the Windows client: the tunnel stays open while any RDP connection
 * is open, and closes [graceMillis] after the last one ends (or if none is
 * opened within [startMillis]).
 */
class Tunnel(
    private val host: String,
    private val port: Int,
    private val username: String,
    private val pinnedFingerprint: String,
    private val localPort: Int,
    private val listener: Listener,
    private val startMillis: Long = 5 * 60_000,
    private val graceMillis: Long = 2 * 60_000,
) {
    interface Listener {
        fun onActiveChanged(active: Int)
        fun onClosed(reason: String)
    }

    private var session: Session? = null
    private var server: ServerSocket? = null
    private val active = AtomicInteger()
    private val closed = AtomicBoolean()
    private val timer = Executors.newSingleThreadScheduledExecutor()
    private var idleTask: ScheduledFuture<*>? = null

    val localAddress: String get() = "127.0.0.1:$boundPort"

    companion object {
        init {
            // Use Bouncy Castle for the modern algorithms; Android's JCA lacks
            // X25519 / Ed25519 / ChaCha20-Poly1305 on many versions.
            JSch.setConfig("xdh", "com.jcraft.jsch.bc.XDH")
            JSch.setConfig("keypairgen.eddsa", "com.jcraft.jsch.bc.KeyPairGenEdDSA")
            JSch.setConfig("ssh-ed25519", "com.jcraft.jsch.bc.SignatureEd25519")
            JSch.setConfig("chacha20-poly1305@openssh.com", "com.jcraft.jsch.bc.ChaCha20Poly1305")
        }
    }

    /** Connects, authenticates and forwards to the login's computer. Blocking. */
    fun open(password: String, code: String) {
        connect(password, code)
        listen(null, localPort)
    }

    /** Connects and authenticates only (then [computers] / [listen]). Blocking. */
    fun connect(password: String, code: String) {
        val keys = PinnedHostKey(pinnedFingerprint)
        val jsch = JSch().apply { hostKeyRepository = keys }
        val s = jsch.getSession(username, host, port)
        // Only what the SecuRDP server offers: modern, AEAD-only, ed25519 host key.
        s.setConfig("kex", "curve25519-sha256,curve25519-sha256@libssh.org")
        s.setConfig("server_host_key", "ssh-ed25519")
        s.setConfig("cipher.c2s", "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com")
        s.setConfig("cipher.s2c", "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com")
        s.setConfig("mac.c2s", "hmac-sha2-256-etm@openssh.com")
        s.setConfig("mac.s2c", "hmac-sha2-256-etm@openssh.com")
        s.setConfig("StrictHostKeyChecking", "yes")
        s.setConfig("PreferredAuthentications", "keyboard-interactive")
        s.userInfo = Answers(password, code)
        s.setServerAliveInterval(30_000)
        s.setServerAliveCountMax(3)
        try {
            s.connect(15_000)
        } catch (e: JSchException) {
            // The host key is checked before login, so a mismatch is reported first.
            val seen = keys.seen
            if (seen != null && seen != pinnedFingerprint) {
                if (pinnedFingerprint.isEmpty()) throw UnknownHostException(seen)
                throw HostChangedException(pinnedFingerprint, seen)
            }
            val msg = e.message.orEmpty()
            if (msg.startsWith("Auth fail") || msg.startsWith("Auth cancel")) throw LoginFailedException()
            throw e
        }
        session = s
        thread(name = "securdp-watch", isDaemon = true) { watch() }
        // Also covers a picker that is never answered.
        scheduleIdle(startMillis)
    }

    /** Which hub computer connections go to (null = the login's computer). */
    @Volatile var computer: String? = null
        private set

    /** The local port Remote Desktop should connect to, once listening. */
    @Volatile var boundPort: Int = localPort
        private set

    /**
     * Asks the gate which computers this login may reach. Older gates don't
     * support it: they return an empty list after a short wait.
     */
    fun computers(): List<HubComputer> {
        val s = session ?: return emptyList()
        val pool = Executors.newSingleThreadExecutor()
        val task = pool.submit<List<HubComputer>> {
            val ch = (s.openChannel("direct-tcpip") as ChannelDirectTCPIP).apply {
                setHost("list.securdp")
                setPort(0)
            }
            val input = ch.inputStream
            ch.connect(5_000)
            try {
                parseComputers(input.readBytes().toString(Charsets.UTF_8))
            } finally {
                ch.disconnect()
            }
        }
        return try {
            task.get(4, TimeUnit.SECONDS)
        } catch (_: Exception) {
            task.cancel(true)
            emptyList()
        } finally {
            pool.shutdownNow()
        }
    }

    /** Starts the loopback listener forwarding to [computer] (null = the login's). */
    fun listen(computer: String?, localPort: Int) {
        val s = session ?: throw IllegalStateException("not connected")
        // Built outside apply{}: inside it, `localPort` would be ServerSocket's own (-1).
        val bindAddr = InetSocketAddress(InetAddress.getByName("127.0.0.1"), localPort)
        val ss = try {
            ServerSocket().apply {
                reuseAddress = true
                bind(bindAddr)
            }
        } catch (e: Exception) {
            s.disconnect()
            throw Exception("Local port $localPort is busy: ${e.message}")
        }
        this.computer = computer
        boundPort = localPort
        server = ss
        thread(name = "securdp-accept", isDaemon = true) { acceptLoop(ss) }
        scheduleIdle(startMillis)
    }

    fun close(reason: String = "Disconnected") {
        if (!closed.compareAndSet(false, true)) return
        runCatching { server?.close() }
        runCatching { session?.disconnect() }
        timer.shutdownNow()
        listener.onClosed(reason)
    }

    private fun watch() {
        while (!closed.get()) {
            Thread.sleep(2_000)
            if (session?.isConnected != true) {
                close("Connection to the server was lost")
                return
            }
        }
    }

    @Synchronized
    private fun scheduleIdle(delay: Long) {
        idleTask?.cancel(false)
        if (closed.get()) return
        idleTask = timer.schedule({ close("Closed: no Remote Desktop connection") }, delay, TimeUnit.MILLISECONDS)
    }

    @Synchronized
    private fun cancelIdle() {
        idleTask?.cancel(false)
        idleTask = null
    }

    private fun acceptLoop(ss: ServerSocket) {
        while (!closed.get()) {
            val sock = try { ss.accept() } catch (_: Exception) { return }
            thread(name = "securdp-conn", isDaemon = true) { forward(sock) }
        }
    }

    private fun forward(sock: Socket) {
        val s = session ?: return sock.close()
        val ch = try {
            // A computer name asks the hub for that PC; 127.0.0.1 means the
            // login's computer (what older gates expect).
            (s.openChannel("direct-tcpip") as ChannelDirectTCPIP).apply {
                setHost(computer ?: "127.0.0.1")
                setPort(3389)
            }
        } catch (_: Exception) {
            sock.close(); return
        }
        val fromServer = ch.inputStream
        val toServer = ch.outputStream
        try {
            ch.connect(10_000)
        } catch (_: Exception) {
            sock.close(); return
        }
        cancelIdle()
        listener.onActiveChanged(active.incrementAndGet())
        try {
            sock.tcpNoDelay = true
            val up = thread(isDaemon = true) { pump(sock.getInputStream(), toServer) }
            pump(fromServer, sock.getOutputStream())
            runCatching { sock.close() }
            up.join(2_000)
        } finally {
            runCatching { sock.close() }
            runCatching { ch.disconnect() }
            val n = active.decrementAndGet()
            listener.onActiveChanged(n)
            if (n == 0) scheduleIdle(graceMillis)
        }
    }

    private fun pump(input: InputStream, output: OutputStream) {
        val buf = ByteArray(32 * 1024)
        try {
            while (true) {
                val n = input.read(buf)
                if (n < 0) break
                output.write(buf, 0, n)
                output.flush()
            }
        } catch (_: Exception) {
        } finally {
            runCatching { output.close() }
        }
    }
}
