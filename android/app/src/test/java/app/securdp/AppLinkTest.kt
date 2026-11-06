package app.securdp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.math.BigInteger
import java.net.URL
import java.security.KeyPairGenerator
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

class AppLinkTest {
    private fun newKey() = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()

    @Test
    fun signatureIsConvertedToSshForm() {
        // DER of r=0x80 (needs a leading zero) and s=0x01.
        val der = byteArrayOf(0x30, 7, 0x02, 2, 0x00, 0x80.toByte(), 0x02, 1, 0x01)
        val sig = derToSshSignature(der)
        val alg = "ecdsa-sha2-nistp256".toByteArray()
        val inner = byteArrayOf(0, 0, 0, 2, 0x00, 0x80.toByte(), 0, 0, 0, 1, 0x01)
        assertEquals(
            (byteArrayOf(0, 0, 0, alg.size.toByte()) + alg + byteArrayOf(0, 0, 0, inner.size.toByte()) + inner).toList(),
            sig.toList(),
        )
    }

    @Test
    fun publicKeyBlobHasFixedSizePoint() {
        val pub = newKey().public as ECPublicKey
        val blob = sshPublicKeyBlob(pub)
        // string alg (4+19) + string "nistp256" (4+8) + string point (4+65)
        assertEquals(4 + 19 + 4 + 8 + 4 + 65, blob.size)
        assertEquals(4.toByte(), blob[4 + 19 + 4 + 8 + 4])
        assertEquals(pub.w.affineX, BigInteger(1, blob.copyOfRange(blob.size - 64, blob.size - 32)))
        assertTrue(authorizedKey(pub, "My Phone").matches(Regex("ecdsa-sha2-nistp256 [A-Za-z0-9+/=]+ My-Phone")))
    }

    @Test
    fun hubInfoSaysWhetherLinksAreAllowed() {
        assertTrue(parseHubInfo("s\tstatus\thttp\t/\nA\t1\n").appLinks)
        assertEquals(false, parseHubInfo("s\tstatus\thttp\t/\n").appLinks)
    }

    @Test
    fun hubInfoOffersTheAndroidApp() {
        val info = parseHubInfo("V\t1.9.0\nP\t9\t1.9.0\nc\tdesktop\t1\t1\n")
        assertEquals(9, info.apkCode)
        assertEquals("1.9.0", info.apkName)
        assertEquals(0, parseHubInfo("c\tdesktop\t1\t1\n").apkCode)
    }

    /** The hub's Android app downloads intact (test gate started with SECURDP_SERVE_APK). */
    @Test
    fun downloadsTheHubsAndroidApp() {
        val e2ePort: Int = System.getProperty("securdp.e2e.port")?.toInt()
            ?: run { assumeTrue("set -Dsecurdp.e2e.port", false); return }
        val apk = System.getProperty("securdp.e2e.apk") ?: run { assumeTrue("set -Dsecurdp.e2e.apk", false); return }
        val noop = object : Tunnel.Listener {
            override fun onActiveChanged(active: Int) {}
            override fun onClosed(reason: String) {}
        }
        val pinned = try {
            Tunnel("127.0.0.1", e2ePort, "probe.user", "", 0, noop).connect("x", "000000")
            error("expected UnknownHostException")
        } catch (e: UnknownHostException) {
            e.fingerprint
        }
        val t = Tunnel("127.0.0.1", e2ePort, "probe.user", pinned, 0, noop)
        t.connect("Test-passphrase-123", TunnelTest.totp("JBSWY3DPEHPK3PXP", -1))
        try {
            val info = t.info()
            assertEquals(99, info.apkCode)
            val out = java.io.ByteArrayOutputStream()
            var last = 0L
            assertEquals("9.9.9", t.downloadApk(out) { done, _ -> last = done })
            val want = java.io.File(apk).readBytes()
            assertTrue(out.toByteArray().contentEquals(want))
            assertEquals(want.size.toLong(), last)
        } finally {
            t.close()
        }
    }

    @Test
    fun suggestsThePagesOwnPort() {
        val pet = HubService("pet", "http", "/", "127.0.0.1:11435")
        assertEquals(11435, suggestedLinkPort(pet, emptySet()))
        assertEquals(18100, suggestedLinkPort(pet, setOf(11435)))
        assertEquals(18100, suggestedLinkPort(HubService("router", "http", "/", "192.168.1.1:80"), emptySet()))
    }

    /**
     * Pair, use the link without a login, reconnect after idle, unpair.
     * Against the Go test gate (user probe.four may pair), with -Dsecurdp.e2e.port.
     */
    @Test
    fun pairAndUseAgainstTestGate() {
        val e2ePort: Int = System.getProperty("securdp.e2e.port")?.toInt()
            ?: run { assumeTrue("set -Dsecurdp.e2e.port", false); return }
        // A kept-alive HTTP connection rightly keeps the link up; this test wants it idle.
        System.setProperty("http.keepAlive", "false")
        val noop = object : Tunnel.Listener {
            override fun onActiveChanged(active: Int) {}
            override fun onClosed(reason: String) {}
        }
        val pinned = try {
            Tunnel("127.0.0.1", e2ePort, "probe.four", "", 0, noop).connect("x", "000000")
            error("expected UnknownHostException")
        } catch (e: UnknownHostException) {
            e.fingerprint
        }
        val kp = newKey()
        val pub = kp.public as ECPublicKey
        val t = Tunnel("127.0.0.1", e2ePort, "probe.four", pinned, 0, noop)
        t.connect("Test-passphrase-123", TunnelTest.totp("JBSWY3DPEHPK3PXP"))
        try {
            assertTrue(t.info().appLinks)
            t.pair("test phone", "status", authorizedKey(pub, "test"))
        } finally {
            t.close()
        }

        val statuses = mutableListOf<String>()
        val link = AppLink(
            "127.0.0.1", e2ePort, "probe.four", pinned, "status", 13470, softwareIdentity(pub, kp.private),
            idleMillis = 300, onStatus = { synchronized(statuses) { statuses += it } },
        )
        link.start()
        try {
            assertEquals(false, link.connected) // nothing until an app connects
            assertTrue(URL("http://127.0.0.1:13470/").readText().contains("Home status page"))
            Thread.sleep(1_000) // idle: the link logs out...
            assertEquals(false, link.connected)
            assertTrue(URL("http://127.0.0.1:13470/").readText().contains("Home status page")) // ...and back in
            assertTrue(statuses.toString(), synchronized(statuses) { "Connected" in statuses })

            // Unpaired on the hub: the next request fails and the reason is shown.
            val t2 = Tunnel("127.0.0.1", e2ePort, "probe.four", pinned, 0, noop)
            t2.connect("Test-passphrase-123", TunnelTest.totp("JBSWY3DPEHPK3PXP", 1))
            try { t2.unpair("test phone") } finally { t2.close() }
            Thread.sleep(1_000)
            assertTrue(runCatching { URL("http://127.0.0.1:13470/").readText() }.isFailure)
            assertTrue(statuses.toString(), synchronized(statuses) { statuses.last().contains("refused this phone's key") })
        } finally {
            link.stop()
        }
    }
}
