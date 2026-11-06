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

data class HubFolder(val name: String, val writable: Boolean)
/** [target] is the page's own host:port on the home network (1.6+ hubs), "" if unknown. */
data class HubService(val name: String, val scheme: String, val path: String, val target: String = "")
/**
 * [appLinks]: this login may pair app links (1.7+ hubs). [apkCode] / [apkName]:
 * the Android app the hub can hand out (1.9+ hubs; 0 = none).
 */
data class HubInfo(
    val computers: List<HubComputer>, val folders: List<HubFolder>, val services: List<HubService>,
    val appLinks: Boolean = false, val apkCode: Int = 0, val apkName: String = "",
)

/** One entry of a shared folder listing. */
data class HubFile(val name: String, val dir: Boolean, val size: Long, val mtime: Long)

/** Parses "hub.securdp": c/f/s lines, tab-separated. */
fun parseHubInfo(text: String): HubInfo {
    val c = mutableListOf<HubComputer>()
    val f = mutableListOf<HubFolder>()
    val s = mutableListOf<HubService>()
    var links = false
    var apkCode = 0
    var apkName = ""
    for (line in text.lines()) {
        val p = line.split("\t")
        when {
            p[0] == "c" && p.size == 4 -> c += HubComputer(p[1], p[2] == "1", p[3] == "1")
            p[0] == "f" && p.size == 3 -> f += HubFolder(p[1], p[2] == "1")
            p[0] == "s" && p.size == 4 -> s += HubService(p[1], p[2], p[3])
            p[0] == "S" && p.size == 3 -> s.replaceAll { if (it.name == p[1]) it.copy(target = p[2]) else it }
            p[0] == "A" && p.size == 2 -> links = p[1] == "1"
            p[0] == "P" && p.size == 3 -> { apkCode = p[1].toIntOrNull() ?: 0; apkName = p[2] }
        }
    }
    return HubInfo(c, f, s, links, apkCode, apkName)
}

/** Parses a folder listing: "d|f \t size \t mtime \t name" lines. */
fun parseListing(text: String): List<HubFile> = text.lines().mapNotNull { line ->
    val p = line.split("\t", limit = 4)
    if (p.size == 4) HubFile(p[3], p[0] == "d", p[1].toLongOrNull() ?: 0, p[2].toLongOrNull() ?: 0) else null
}

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

/**
 * A JSch session set up for a SecuRDP gate: only what the gate offers (modern,
 * AEAD-only, ed25519 host key) and only the pinned host key.
 */
internal fun gateSession(host: String, port: Int, username: String, keys: HostKeyRepository, jsch: JSch = JSch()): Session {
    jsch.hostKeyRepository = keys
    val s = jsch.getSession(username, host, port)
    s.setConfig("kex", "curve25519-sha256,curve25519-sha256@libssh.org")
    s.setConfig("server_host_key", "ssh-ed25519")
    s.setConfig("cipher.c2s", "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com")
    s.setConfig("cipher.s2c", "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com")
    s.setConfig("mac.c2s", "hmac-sha2-256-etm@openssh.com")
    s.setConfig("mac.s2c", "hmac-sha2-256-etm@openssh.com")
    s.setConfig("StrictHostKeyChecking", "yes")
    return s
}

/** Accepts only the pinned key; remembers what the server presented. */
internal fun pinnedHostKey(pinned: String): HostKeyRepository = PinnedHostKey(pinned)

/** What the gate presented, for telling "unknown/changed host" from "login refused". */
internal fun HostKeyRepository.seenFingerprint(): String? = (this as? PinnedHostKey)?.seen

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
    private val servers = mutableListOf<ServerSocket>()
    private val active = AtomicInteger()
    private val holds = AtomicInteger() // files / web pages in use
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
        val s = gateSession(host, port, username, keys)
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
        bindLocal(localPort, computer ?: "127.0.0.1", 3389, rdp = true)
        this.computer = computer
        boundPort = localPort
        scheduleIdle(startMillis)
    }

    /** Forwards [localPort] to the hub's web service [name] (granted per user on the hub). */
    fun listenService(name: String, localPort: Int) {
        synchronized(svcBound) {
            if (name in svcBound) return // reopening the page reuses its listener
            bindLocal(localPort, "svc.$name", 0, rdp = false)
            svcBound += name
        }
    }
    private val svcBound = mutableSetOf<String>()

    private fun bindLocal(localPort: Int, destHost: String, destPort: Int, rdp: Boolean) {
        val s = session ?: throw IllegalStateException("not connected")
        // Built outside apply{}: inside it, `localPort` would be ServerSocket's own (-1).
        val bindAddr = InetSocketAddress(InetAddress.getByName("127.0.0.1"), localPort)
        val ss = try {
            ServerSocket().apply {
                reuseAddress = true
                bind(bindAddr)
            }
        } catch (e: Exception) {
            if (rdp) s.disconnect()
            throw Exception("Local port $localPort is busy: ${e.message}")
        }
        synchronized(servers) { servers += ss }
        thread(name = "securdp-accept", isDaemon = true) { acceptLoop(ss, destHost, destPort, rdp) }
    }

    /**
     * Keeps the tunnel open (here and on the hub) while files or a web page
     * are in use. Close the returned handle to let go.
     */
    fun hold(): AutoCloseable {
        val s = session ?: throw IllegalStateException("not connected")
        val ch = (s.openChannel("direct-tcpip") as ChannelDirectTCPIP).apply {
            setHost("hold.securdp")
            setPort(0)
        }
        ch.connect(5_000)
        holds.incrementAndGet()
        cancelIdle()
        val released = AtomicBoolean()
        return AutoCloseable {
            if (released.compareAndSet(false, true)) {
                ch.disconnect()
                if (holds.decrementAndGet() == 0 && active.get() == 0) scheduleIdle(graceMillis)
            }
        }
    }

    /** Everything the hub offers this login. Falls back to [computers] on older hubs. */
    fun info(): HubInfo {
        val text = runCatching { readPseudo("hub.securdp") }.getOrNull()
        val info = text?.let { parseHubInfo(it) }
        if (info != null && (info.computers.size + info.folders.size + info.services.size) > 0) return info
        return HubInfo(computers(), emptyList(), emptyList())
    }

    /**
     * Pairs this device's [publicKey] (authorized_keys format) as an app link
     * to the web page [service]. Needs a password + code login (this one).
     */
    fun pair(device: String, service: String, publicKey: String) = linkRequest("pair\t$device\t$service\t$publicKey")

    /** Removes a paired device from the hub. */
    fun unpair(device: String) = linkRequest("unpair\t$device")

    /**
     * Downloads the Android app the hub offers into [out], checking its size
     * and SHA-256. [progress] gets (bytes so far, total). Returns its versionName.
     */
    fun downloadApk(out: OutputStream, progress: (Long, Long) -> Unit = { _, _ -> }): String {
        val s = session ?: throw IllegalStateException("not connected")
        val ch = (s.openChannel("direct-tcpip") as ChannelDirectTCPIP).apply {
            setHost("apk.securdp")
            setPort(0)
        }
        val input = ch.inputStream
        try {
            try {
                ch.connect(10_000)
            } catch (e: Exception) {
                throw Exception("The hub has no Android app to offer")
            }
            val f = (readLine(input) ?: throw Exception("No reply from the hub")).split("\t")
            if (f[0] != "ok" || f.size != 4) throw Exception(f.getOrNull(1) ?: "Unexpected reply from the hub")
            val size = f[1].toLongOrNull()?.takeIf { it in 1..(256L shl 20) } ?: throw Exception("Unexpected app size")
            val md = MessageDigest.getInstance("SHA-256")
            val buf = ByteArray(64 * 1024)
            var done = 0L
            while (done < size) {
                val n = input.read(buf, 0, minOf(buf.size.toLong(), size - done).toInt())
                if (n < 0) throw Exception("Download stopped after $done of $size bytes")
                out.write(buf, 0, n)
                md.update(buf, 0, n)
                done += n
                progress(done, size)
            }
            val sum = md.digest().joinToString("") { "%02x".format(it) }
            if (sum != f[2]) throw Exception("The download was damaged (checksum mismatch)")
            return f[3]
        } finally {
            ch.disconnect()
        }
    }

    private fun linkRequest(line: String) {
        val s = session ?: throw IllegalStateException("not connected")
        val ch = (s.openChannel("direct-tcpip") as ChannelDirectTCPIP).apply {
            setHost("pair.securdp")
            setPort(0)
        }
        val input = ch.inputStream
        try {
            ch.connect(10_000)
            ch.outputStream.apply { write("$line\n".toByteArray()); flush() }
            val reply = readLine(input) ?: throw Exception("This hub doesn't support app links (update it to 1.7)")
            val f = reply.split("\t", limit = 2)
            if (f[0] != "ok") throw Exception(f.getOrNull(1) ?: "The hub refused")
        } finally {
            ch.disconnect()
        }
    }

    private fun readPseudo(host: String): String {
        val s = session ?: throw IllegalStateException("not connected")
        val pool = Executors.newSingleThreadExecutor()
        val task = pool.submit<String> {
            val ch = (s.openChannel("direct-tcpip") as ChannelDirectTCPIP).apply {
                setHost(host)
                setPort(0)
            }
            val input = ch.inputStream
            ch.connect(5_000)
            try {
                input.readBytes().toString(Charsets.UTF_8)
            } finally {
                ch.disconnect()
            }
        }
        return try {
            task.get(4, TimeUnit.SECONDS)
        } finally {
            task.cancel(true)
            pool.shutdownNow()
        }
    }

    // ---- files: one request per channel (see the hub's files package) ----

    /** A file response: the body stream (close it) and the status number. */
    class FileReply(val body: InputStream, val n: Long, private val ch: ChannelDirectTCPIP) : AutoCloseable {
        override fun close() { runCatching { ch.disconnect() } }
    }

    fun fileRequest(op: String, vararg args: String, body: InputStream? = null, bodySize: Long = 0): FileReply {
        val s = session ?: throw IllegalStateException("not connected")
        val ch = (s.openChannel("direct-tcpip") as ChannelDirectTCPIP).apply {
            setHost("files.securdp")
            setPort(0)
        }
        val input = ch.inputStream
        val output = ch.outputStream
        try {
            ch.connect(10_000)
        } catch (e: Exception) {
            throw Exception("File access refused by the hub")
        }
        try {
            output.write((listOf(op) + args).joinToString("\t").plus("\n").toByteArray())
            if (body != null) {
                val buf = ByteArray(64 * 1024)
                var left = bodySize
                while (left > 0) {
                    val n = body.read(buf, 0, minOf(buf.size.toLong(), left).toInt())
                    if (n < 0) break
                    output.write(buf, 0, n)
                    left -= n
                }
            }
            output.flush()
            val status = readLine(input) ?: throw Exception("No reply from the hub")
            val f = status.split("\t", limit = 2)
            if (f[0] != "ok") throw Exception(f.getOrNull(1) ?: "Request failed")
            return FileReply(input, f.getOrNull(1)?.toLongOrNull() ?: 0, ch)
        } catch (e: Exception) {
            ch.disconnect()
            throw e
        }
    }

    private fun simple(op: String, vararg args: String) = fileRequest(op, *args).close()

    /** Lists a folder; "" lists the shared folders themselves. */
    fun list(path: String): List<HubFile> =
        if (path.isEmpty()) fileRequest("roots").use { r ->
            r.body.readBytes().toString(Charsets.UTF_8).lines().mapNotNull { l ->
                val f = l.split("\t")
                if (f.size == 2) HubFile(f[0], true, 0, 0) else null
            }
        } else fileRequest("list", path).use { r -> parseListing(r.body.readBytes().toString(Charsets.UTF_8)) }

    /** Streams a file; the reply's n is the file's total size. */
    fun get(path: String, offset: Long = 0): FileReply = fileRequest("get", path, offset.toString())

    fun thumb(path: String, px: Int): ByteArray = fileRequest("thumb", path, px.toString()).use { r ->
        val b = ByteArray(r.n.toInt())
        var off = 0
        while (off < b.size) {
            val n = r.body.read(b, off, b.size - off)
            if (n < 0) throw Exception("thumbnail cut short")
            off += n
        }
        b
    }

    fun put(path: String, size: Long, body: InputStream) =
        fileRequest("put", path, size.toString(), body = body, bodySize = size).close()

    fun mkdir(path: String) = simple("mkdir", path)
    fun delete(path: String) = simple("delete", path)
    fun rename(from: String, to: String) = simple("rename", from, to)

    private fun readLine(input: InputStream): String? {
        val out = java.io.ByteArrayOutputStream()
        while (true) {
            val b = input.read()
            if (b < 0) return if (out.size() == 0) null else out.toString("UTF-8")
            if (b == '\n'.code) return out.toString("UTF-8")
            out.write(b)
            if (out.size() > 8192) return null
        }
    }

    fun close(reason: String = "Disconnected") {
        if (!closed.compareAndSet(false, true)) return
        synchronized(servers) { servers.forEach { runCatching { it.close() } } }
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

    private fun acceptLoop(ss: ServerSocket, destHost: String, destPort: Int, rdp: Boolean) {
        while (!closed.get()) {
            val sock = try { ss.accept() } catch (_: Exception) { return }
            thread(name = "securdp-conn", isDaemon = true) {
                if (rdp) forward(sock, destHost, destPort) else relay(sock, destHost, destPort)
            }
        }
    }

    /** Web service connection: forwarded, but not counted as a Remote Desktop session. */
    private fun relay(sock: Socket, destHost: String, destPort: Int) {
        val s = session ?: return sock.close()
        val ch = try {
            (s.openChannel("direct-tcpip") as ChannelDirectTCPIP).apply {
                setHost(destHost)
                setPort(destPort)
            }
        } catch (_: Exception) {
            sock.close(); return
        }
        val fromServer = ch.inputStream
        val toServer = ch.outputStream
        try {
            ch.connect(10_000)
            val up = thread(isDaemon = true) { pump(sock.getInputStream(), toServer) }
            pump(fromServer, sock.getOutputStream())
            runCatching { sock.close() }
            up.join(2_000)
        } catch (_: Exception) {
        } finally {
            runCatching { sock.close() }
            runCatching { ch.disconnect() }
        }
    }

    private fun forward(sock: Socket, destHost: String, destPort: Int) {
        val s = session ?: return sock.close()
        val ch = try {
            // A computer name asks the hub for that PC; 127.0.0.1 means the
            // login's computer (what older gates expect).
            (s.openChannel("direct-tcpip") as ChannelDirectTCPIP).apply {
                setHost(destHost)
                setPort(destPort)
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
            if (n == 0 && holds.get() == 0) scheduleIdle(graceMillis)
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
