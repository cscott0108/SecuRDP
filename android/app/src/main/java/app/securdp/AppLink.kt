package app.securdp

import com.jcraft.jsch.ChannelDirectTCPIP
import com.jcraft.jsch.Identity
import com.jcraft.jsch.JSch
import com.jcraft.jsch.JSchException
import com.jcraft.jsch.Session
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread

/**
 * An app link: 127.0.0.1:[localPort] on this phone reaches the hub web page
 * [service], logging in with this device's paired key (no prompts).
 *
 * The port listens all the time, but the SSH connection is only opened when
 * an app connects, and closed again [idleMillis] after the last connection
 * ends, so nothing runs while the app is quiet. A dropped network just means
 * the next connection logs in again.
 */
class AppLink(
    private val host: String,
    private val port: Int,
    private val username: String,
    private val pinnedFingerprint: String,
    private val service: String,
    private val localPort: Int,
    private val identity: Identity,
    private val idleMillis: Long = 60_000,
    private val onStatus: (String) -> Unit = {},
) {
    private var server: ServerSocket? = null
    private var session: Session? = null
    private val active = AtomicInteger()
    private val stopped = AtomicBoolean()
    private val timer = Executors.newSingleThreadScheduledExecutor()
    private var idleTask: ScheduledFuture<*>? = null

    /** Starts listening. Throws if the port is taken (e.g. by another app). */
    fun start() {
        // Built outside apply{}: inside it, `localPort` would be ServerSocket's own (-1).
        val bindAddr = InetSocketAddress(InetAddress.getByName("127.0.0.1"), localPort)
        val ss = ServerSocket().apply {
            reuseAddress = true
            bind(bindAddr)
        }
        server = ss
        onStatus("Ready")
        thread(name = "securdp-link-accept", isDaemon = true) {
            while (!stopped.get()) {
                val sock = try { ss.accept() } catch (_: Exception) { break }
                thread(name = "securdp-link", isDaemon = true) { relay(sock) }
            }
        }
    }

    fun stop() {
        if (!stopped.compareAndSet(false, true)) return
        runCatching { server?.close() }
        disconnect()
        timer.shutdownNow()
    }

    @Synchronized
    private fun disconnect() {
        runCatching { session?.disconnect() }
        session = null
    }

    /** The logged-in session, connecting (or reconnecting) if needed. */
    @Synchronized
    private fun session(): Session {
        session?.let { if (it.isConnected) return it }
        val keys = pinnedHostKey(pinnedFingerprint)
        val jsch = JSch().apply { addIdentity(identity, null) }
        val s = gateSession(host, port, username, keys, jsch)
        s.setConfig("PreferredAuthentications", "publickey")
        s.setServerAliveInterval(15_000)
        s.setServerAliveCountMax(2)
        try {
            s.connect(15_000)
        } catch (e: JSchException) {
            val seen = keys.seenFingerprint()
            throw when {
                seen != null && seen != pinnedFingerprint -> HostChangedException(pinnedFingerprint, seen)
                e.message.orEmpty().startsWith("Auth") ->
                    Exception("The hub refused this phone's key - it may have been removed there. Pair again.")
                else -> Exception("Can't reach the hub: ${e.message}")
            }
        }
        session = s
        return s
    }

    private class Opened(val ch: ChannelDirectTCPIP, val fromHub: InputStream, val toHub: OutputStream)

    /** Opens a channel to the page; a session that died with the network gets one fresh login. */
    private fun open(): Opened {
        for (attempt in 0..1) {
            val ch = (session().openChannel("direct-tcpip") as ChannelDirectTCPIP).apply {
                setHost("svc.$service")
                setPort(0)
            }
            val fromHub = ch.inputStream // before connect, so nothing is missed
            val toHub = ch.outputStream
            try {
                ch.connect(10_000)
                return Opened(ch, fromHub, toHub)
            } catch (e: JSchException) {
                ch.disconnect()
                disconnect()
                if (attempt == 1) throw Exception("The hub didn't open $service (is it running?)")
            }
        }
        error("unreachable")
    }

    private fun relay(sock: Socket) {
        cancelIdle()
        active.incrementAndGet()
        var o: Opened? = null
        try {
            o = open()
            onStatus("Connected")
            pumpBoth(sock, o.fromHub, o.toHub)
        } catch (e: Exception) {
            onStatus(e.message ?: "Couldn't connect")
        } finally {
            runCatching { sock.close() }
            runCatching { o?.ch?.disconnect() }
            if (active.decrementAndGet() == 0) scheduleIdle()
        }
    }

    private fun pumpBoth(sock: Socket, fromHub: InputStream, toHub: OutputStream) {
        val up = thread(isDaemon = true) { pump(sock.getInputStream(), toHub) }
        pump(fromHub, sock.getOutputStream())
        runCatching { sock.close() }
        up.join(2_000)
    }

    @Synchronized
    private fun scheduleIdle() {
        idleTask?.cancel(false)
        if (stopped.get()) return
        idleTask = timer.schedule({
            if (active.get() == 0) {
                disconnect()
                onStatus("Ready")
            }
        }, idleMillis, TimeUnit.MILLISECONDS)
    }

    @Synchronized
    private fun cancelIdle() {
        idleTask?.cancel(false)
        idleTask = null
    }

    /** True while logged in to the hub (between an app's request and the idle timeout). */
    val connected: Boolean @Synchronized get() = session?.isConnected == true

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
