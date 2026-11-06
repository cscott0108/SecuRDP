package app.securdp

import java.net.URI

/** Where a link from a tunnelled hub web page should go. */
sealed interface LinkRoute {
    /** Already the tunnel's own address: load as-is. */
    data object Tunnel : LinkRoute
    /** Points at the web page's real home address: load this tunnel URL instead. */
    data class Rewrite(val url: String) : LinkRoute
    /** Another address on the home network: not reachable through this tunnel. */
    data class Unreachable(val host: String) : LinkRoute
    /** A normal internet address: hand it to the phone's browser. */
    data object Internet : LinkRoute
    /** blob:, data:, javascript: and other in-page schemes: let the page handle it. */
    data object Other : LinkRoute
}

/**
 * Routes [url] for a hub web page served on 127.0.0.1:[localPort], whose real
 * address on the home network is [target] (host:port, "" if the hub didn't say).
 * Pages often build full-size image links from their real address, which the
 * phone can't reach directly; those go back through the tunnel.
 */
fun routeLink(url: String, localPort: Int, target: String): LinkRoute {
    val u = runCatching { URI(url) }.getOrNull() ?: return LinkRoute.Other
    val scheme = u.scheme?.lowercase() ?: return LinkRoute.Other
    if (scheme != "http" && scheme != "https") return LinkRoute.Other
    val host = u.host?.lowercase() ?: return LinkRoute.Other
    val port = if (u.port > 0) u.port else if (scheme == "https") 443 else 80
    if ((host == "127.0.0.1" || host == "localhost") && port == localPort) return LinkRoute.Tunnel
    if (target.isNotEmpty() && "$host:$port".equals(normalizeTarget(target), ignoreCase = true)) {
        val rest = (u.rawPath ?: "") + (u.rawQuery?.let { "?$it" } ?: "") + (u.rawFragment?.let { "#$it" } ?: "")
        return LinkRoute.Rewrite("$scheme://127.0.0.1:$localPort$rest")
    }
    return if (isHomeAddress(host)) LinkRoute.Unreachable(host) else LinkRoute.Internet
}

private fun normalizeTarget(t: String): String {
    val i = t.lastIndexOf(':')
    return if (i > 0) t.substring(0, i).trim('[', ']').lowercase() + ":" + t.substring(i + 1) else t.lowercase()
}

/** Private / local addresses and single-label or .local/.lan names. */
fun isHomeAddress(host: String): Boolean {
    val h = host.trim('[', ']').lowercase()
    if (h == "localhost" || h.startsWith("127.") || !h.contains('.') || h.endsWith(".local") || h.endsWith(".lan") ||
        h.endsWith(".home") || h.endsWith(".internal")) return true
    val p = h.split('.').mapNotNull { it.toIntOrNull() }
    if (p.size != 4) return false
    return p[0] == 10 || (p[0] == 172 && p[1] in 16..31) || (p[0] == 192 && p[1] == 168) ||
        (p[0] == 169 && p[1] == 254) || (p[0] == 100 && p[1] in 64..127)
}
