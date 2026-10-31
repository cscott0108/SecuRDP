package app.securdp

import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.net.InetSocketAddress
import java.net.Socket

/**
 * Talks to a real SecuRDP gate (default: this PC's service). It stops at the
 * host-key check, which happens before login, so it never counts as a failed
 * login on the server. Override with -Dsecurdp.host / -Dsecurdp.port.
 */
class TunnelTest {
    private val host = System.getProperty("securdp.host", "127.0.0.1")
    private val port = System.getProperty("securdp.port", "38062").toInt()

    private fun reachable() = runCatching {
        Socket().use { it.connect(InetSocketAddress(host, port), 2_000) }
    }.isSuccess

    private val noop = object : Tunnel.Listener {
        override fun onActiveChanged(active: Int) {}
        override fun onClosed(reason: String) {}
    }

    @Test
    fun handshakeReportsUnknownHostWithFingerprint() {
        assumeTrue("no SecuRDP server at $host:$port", reachable())
        try {
            Tunnel(host, port, "probe.user", "", 0, noop).open("x", "000000")
            fail("expected UnknownHostException")
        } catch (e: UnknownHostException) {
            println("server fingerprint: ${e.fingerprint}")
            val expected = System.getProperty("securdp.fingerprint")
            if (expected != null) assertEquals(expected, e.fingerprint)
            assert(e.fingerprint.startsWith("SHA256:"))
        }
    }

    @Test
    fun wrongPinnedKeyIsRejectedBeforeLogin() {
        assumeTrue("no SecuRDP server at $host:$port", reachable())
        try {
            Tunnel(host, port, "probe.user", "SHA256:not-the-real-key", 0, noop).open("x", "000000")
            fail("expected HostChangedException")
        } catch (e: HostChangedException) {
            assert(e.got.startsWith("SHA256:"))
        }
    }

    /**
     * Full login + tunnel against the Go test gate
     * (`SECURDP_SERVE_ADDR=127.0.0.1:38999 go test ./internal/server -run TestServeForExternalClient`),
     * enabled with -Dsecurdp.e2e.port=38999.
     */
    @Test
    fun fullLoginAndTunnelAgainstTestGate() {
        val e2ePort: Int = System.getProperty("securdp.e2e.port")?.toInt()
            ?: run { assumeTrue("set -Dsecurdp.e2e.port", false); return }
        val local = 13450
        val pinned = try {
            Tunnel("127.0.0.1", e2ePort, "probe.user", "", local, noop).open("x", "000000")
            error("expected UnknownHostException")
        } catch (e: UnknownHostException) {
            e.fingerprint
        }

        // Wrong code: login refused with a friendly message, no extra retries.
        try {
            Tunnel("127.0.0.1", e2ePort, "probe.user", pinned, local, noop).open("Test-passphrase-123", "000000")
            fail("wrong code accepted")
        } catch (_: LoginFailedException) {
        }

        val closed = java.util.concurrent.CountDownLatch(1)
        var lastActive = -1
        val t = Tunnel("127.0.0.1", e2ePort, "probe.user", pinned, local, object : Tunnel.Listener {
            override fun onActiveChanged(active: Int) { lastActive = active }
            override fun onClosed(reason: String) { closed.countDown() }
        }, graceMillis = 500)
        t.open("Test-passphrase-123", totp("JBSWY3DPEHPK3PXP"))

        Socket("127.0.0.1", local).use { s ->
            s.soTimeout = 5_000
            s.getOutputStream().write("hello rdp".toByteArray())
            val buf = ByteArray(9)
            var n = 0
            while (n < 9) n += s.getInputStream().read(buf, n, 9 - n)
            assertEquals("hello rdp", String(buf))
        }
        // After the last RDP connection closes, the grace timer shuts the tunnel.
        assert(closed.await(5, java.util.concurrent.TimeUnit.SECONDS)) { "tunnel did not auto-close" }
        assertEquals(0, lastActive)
    }

    /** Hub picker: one login, list the computers, forward to the chosen one. */
    @Test
    fun pickerListAndChooseAgainstTestGate() {
        val e2ePort: Int = System.getProperty("securdp.e2e.port")?.toInt()
            ?: run { assumeTrue("set -Dsecurdp.e2e.port", false); return }
        val pinned = try {
            Tunnel("127.0.0.1", e2ePort, "probe.two", "", 0, noop).connect("x", "000000")
            error("expected UnknownHostException")
        } catch (e: UnknownHostException) {
            e.fingerprint
        }
        val t = Tunnel("127.0.0.1", e2ePort, "probe.two", pinned, 0, noop)
        t.connect("Test-passphrase-123", totp("JBSWY3DPEHPK3PXP"))
        try {
            val list = t.computers()
            assertEquals(listOf("desktop", "laptop"), list.map { it.name })
            assert(list.all { it.online }) { "both test PCs should answer: $list" }
            assert(list.first { it.name == "desktop" }.isDefault)

            t.listen("laptop", 13451)
            Socket("127.0.0.1", 13451).use { s ->
                s.soTimeout = 5_000
                val buf = ByteArray(7)
                var n = 0
                while (n < 7) n += s.getInputStream().read(buf, n, 7 - n)
                assertEquals("laptop;", String(buf))
            }
        } finally {
            t.close()
        }
    }

    @Test
    fun parsesComputerList() {
        assertEquals(
            listOf(HubComputer("desktop", true, true), HubComputer("laptop", false, false)),
            parseComputers("desktop 1 1\nlaptop 0 0\n\ngarbage\n"),
        )
    }

    private fun totp(secret: String): String {
        val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        var bits = 0L; var nbits = 0
        val key = java.io.ByteArrayOutputStream()
        for (c in secret) {
            bits = (bits shl 5) or alphabet.indexOf(c).toLong(); nbits += 5
            if (nbits >= 8) { key.write(((bits shr (nbits - 8)) and 0xff).toInt()); nbits -= 8 }
        }
        val step = System.currentTimeMillis() / 1000 / 30
        val mac = javax.crypto.Mac.getInstance("HmacSHA1").apply { init(javax.crypto.spec.SecretKeySpec(key.toByteArray(), "HmacSHA1")) }
        val h = mac.doFinal(java.nio.ByteBuffer.allocate(8).putLong(step).array())
        val off = h[h.size - 1].toInt() and 0xf
        val code = ((h[off].toInt() and 0x7f) shl 24) or ((h[off + 1].toInt() and 0xff) shl 16) or
            ((h[off + 2].toInt() and 0xff) shl 8) or (h[off + 3].toInt() and 0xff)
        return "%06d".format(code % 1_000_000)
    }

    @Test
    fun fingerprintFormatMatchesOpenSSH() {
        // OpenSSH: SHA256 of the key blob, base64 without padding.
        assertEquals("SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU", fingerprint(ByteArray(0)))
    }
}
