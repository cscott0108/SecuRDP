package app.securdp

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.net.ServerSocket
import java.net.Socket
import java.security.KeyPairGenerator
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread

/**
 * Local -> network drop -> home login comes back by itself -> Switch to remote,
 * all on one local port. Against the Go test gate (probe.six), with -Dsecurdp.e2e.port.
 */
class SwitchTest {
    /** Forwards to the gate; [freeze] silences the connections open so far (Wi-Fi gone). */
    private class FlakyProxy(target: Int) : AutoCloseable {
        val server = ServerSocket(0)
        private val live = CopyOnWriteArrayList<AtomicBoolean>()

        init {
            thread(isDaemon = true) {
                while (true) {
                    val c = runCatching { server.accept() }.getOrNull() ?: break
                    val up = Socket("127.0.0.1", target)
                    val on = AtomicBoolean(true).also { live += it }
                    fun pipe(a: Socket, b: Socket) = thread(isDaemon = true) {
                        val buf = ByteArray(32 * 1024)
                        runCatching {
                            while (true) {
                                val n = a.getInputStream().read(buf)
                                if (n < 0) break
                                if (on.get()) b.getOutputStream().write(buf, 0, n)
                            }
                        }
                        runCatching { b.close() }
                    }
                    pipe(c, up)
                    pipe(up, c)
                }
            }
        }

        fun freeze() = live.forEach { it.set(false) }
        override fun close() = server.close()
    }

    private val noop = object : Tunnel.Listener {
        override fun onActiveChanged(active: Int) {}
        override fun onClosed(reason: String) {}
    }

    @After
    fun reset() {
        Tunnel.aliveIntervalMillis = 10_000
        Tunnel.homeRetryMillis = 10_000L
    }

    private fun waitFor(what: String, cond: () -> Boolean) {
        val end = System.currentTimeMillis() + 15_000
        while (System.currentTimeMillis() < end) {
            if (cond()) return
            Thread.sleep(100)
        }
        throw AssertionError("timed out waiting for $what")
    }

    private fun echo(port: Int, msg: String) = Socket("127.0.0.1", port).use { s ->
        s.soTimeout = 5_000
        s.getOutputStream().write(msg.toByteArray())
        val buf = ByteArray(msg.length)
        var got = 0
        while (got < buf.size) {
            val n = s.getInputStream().read(buf, got, buf.size - got)
            if (n < 0) break
            got += n
        }
        assertEquals(msg, String(buf, 0, got))
    }

    @Test
    fun localDropsComesBackThenSwitchesToRemote() {
        val e2ePort: Int = System.getProperty("securdp.e2e.port")?.toInt()
            ?: run { assumeTrue("set -Dsecurdp.e2e.port", false); return }
        Tunnel.aliveIntervalMillis = 300
        Tunnel.homeRetryMillis = 300
        val pinned = try {
            Tunnel("127.0.0.1", e2ePort, "probe.six", "", 0, noop).connect("x", "000000")
            error("expected UnknownHostException")
        } catch (e: UnknownHostException) {
            e.fingerprint
        }
        val kp = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val full = Tunnel("127.0.0.1", e2ePort, "probe.six", pinned, 0, noop)
        full.connect("Test-passphrase-123", TunnelTest.totp("JBSWY3DPEHPK3PXP", -1))
        try { full.trust("switch test", authorizedKey(kp.public as ECPublicKey, "t")) } finally { full.close() }

        FlakyProxy(e2ePort).use { wifi ->
            val logins = CopyOnWriteArrayList<String>()
            val t = Tunnel(
                "127.0.0.1", wifi.server.localPort, "probe.six", pinned, 0,
                object : Tunnel.Listener {
                    override fun onActiveChanged(active: Int) {}
                    override fun onClosed(reason: String) { logins += "closed: $reason" }
                    override fun onLoginChanged(home: Boolean, lost: Boolean) { logins += "home=$home lost=$lost" }
                },
                remoteHost = "127.0.0.1", remotePort = e2ePort,
            )
            t.connectHome(softwareIdentity(kp.public as ECPublicKey, kp.private))
            try {
                val port = 13531
                t.listen("desktop", port) // the test gate's desktop echoes
                echo(port, "at home")
                assertTrue(t.isHome)

                wifi.freeze()
                waitFor("the drop") { t.isLost }
                waitFor("the home login to come back") { !t.isLost }
                assertTrue(t.isHome)
                echo(port, "back home")

                t.switchRemote("Test-passphrase-123", TunnelTest.totp("JBSWY3DPEHPK3PXP"))
                assertFalse(t.isHome)
                echo(port, "remote now")
                assertTrue(logins.toString(), "home=false lost=false" in logins)
                assertFalse(logins.toString(), logins.any { it.startsWith("closed") })
            } finally {
                t.close()
            }
        }
    }
}
