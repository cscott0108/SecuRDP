package app.securdp

import org.junit.Assert.assertEquals
import org.junit.Test

class WebLinksTest {
    private val port = 13460
    private val target = "192.168.1.50:7865"

    @Test
    fun tunnelLinksLoadAsIs() {
        assertEquals(LinkRoute.Tunnel, routeLink("http://127.0.0.1:13460/file=out/a.png", port, target))
    }

    @Test
    fun realAddressGoesBackThroughTheTunnel() {
        assertEquals(
            LinkRoute.Rewrite("http://127.0.0.1:13460/file=C:/out/a%20b.png?x=1#top"),
            routeLink("http://192.168.1.50:7865/file=C:/out/a%20b.png?x=1#top", port, target),
        )
        // A service the hub reaches on its own loopback (e.g. Plex on 127.0.0.1:32400).
        assertEquals(
            LinkRoute.Rewrite("http://127.0.0.1:13460/web/index.html"),
            routeLink("http://127.0.0.1:32400/web/index.html", port, "127.0.0.1:32400"),
        )
        assertEquals(LinkRoute.Rewrite("https://127.0.0.1:13460/"), routeLink("https://router.lan/", port, "router.lan:443"))
    }

    @Test
    fun otherHomeAddressesAreUnreachable() {
        assertEquals(LinkRoute.Unreachable("192.168.1.60"), routeLink("http://192.168.1.60:8188/view", port, target))
        assertEquals(LinkRoute.Unreachable("nas.local"), routeLink("http://nas.local/", port, target))
        assertEquals(LinkRoute.Unreachable("192.168.1.50"), routeLink("http://192.168.1.50:9999/", port, target))
    }

    @Test
    fun internetAndInPageLinks() {
        assertEquals(LinkRoute.Internet, routeLink("https://github.com/x", port, target))
        assertEquals(LinkRoute.Other, routeLink("blob:http://127.0.0.1:13460/abc", port, target))
        assertEquals(LinkRoute.Other, routeLink("data:image/png;base64,AAA", port, target))
        // Older hubs don't share the target: real-address links are reported, not guessed.
        assertEquals(LinkRoute.Unreachable("192.168.1.50"), routeLink("http://192.168.1.50:7865/a", port, ""))
    }
}
