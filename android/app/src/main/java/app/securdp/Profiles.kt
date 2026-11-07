package app.securdp

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

/** A saved computer. Passwords and authenticator codes are never stored. */
data class Profile(
    val name: String,
    val host: String,
    val port: Int,
    val username: String,
    val rdpUsername: String = "",
    val hostFingerprint: String = "",
    /** Per-profile loopback port, so Remote Desktop keeps a separate saved login for each PC. */
    val localPort: Int = 0,
    /** Hub profiles: the PC to use without asking ("" = show the picker). */
    val computer: String = "",
    /** Hub profiles: a loopback port per hub PC, for the same reason as [localPort]. */
    val computerPorts: Map<String, Int> = emptyMap(),
    /**
     * Trusted home login (the Local button): the Keystore key alias ("" = not
     * trusted), the name it's trusted under on the hub, and the hub's home
     * address (host or host:port, "" = [host]).
     */
    val homeKeyAlias: String = "",
    val homeDevice: String = "",
    val homeHost: String = "",
)

/**
 * An app link paired with a hub: 127.0.0.1:[localPort] reaches [service] on
 * [profile]'s hub using the Keystore key [keyAlias] (see AppLink).
 */
data class LinkConfig(
    val keyAlias: String,
    val profile: String,
    val device: String,
    val service: String,
    val localPort: Int,
    val enabled: Boolean = true,
)

class ProfileStore(context: Context) {
    private val prefs = context.getSharedPreferences("profiles", Context.MODE_PRIVATE)

    fun load(): List<Profile> {
        val arr = JSONArray(prefs.getString("list", "[]"))
        return (0 until arr.length()).map { i ->
            val o = arr.getJSONObject(i)
            val ports = o.optJSONObject("computerPorts")
            Profile(
                name = o.getString("name"),
                host = o.getString("host"),
                port = o.getInt("port"),
                username = o.getString("username"),
                rdpUsername = o.optString("rdpUsername"),
                hostFingerprint = o.optString("hostFingerprint"),
                localPort = o.optInt("localPort"),
                computer = o.optString("computer"),
                computerPorts = ports?.keys()?.asSequence()?.associateWith { ports.getInt(it) } ?: emptyMap(),
                homeKeyAlias = o.optString("homeKeyAlias"),
                homeDevice = o.optString("homeDevice"),
                homeHost = o.optString("homeHost"),
            )
        }
    }

    private fun save(list: List<Profile>) {
        val arr = JSONArray()
        list.forEach {
            arr.put(JSONObject().apply {
                put("name", it.name); put("host", it.host); put("port", it.port)
                put("username", it.username); put("rdpUsername", it.rdpUsername)
                put("hostFingerprint", it.hostFingerprint); put("localPort", it.localPort)
                put("computer", it.computer)
                put("computerPorts", JSONObject(it.computerPorts as Map<*, *>))
                put("homeKeyAlias", it.homeKeyAlias); put("homeDevice", it.homeDevice); put("homeHost", it.homeHost)
            })
        }
        prefs.edit().putString("list", arr.toString()).apply()
    }

    private fun usedPorts(list: List<Profile>): Set<Int> =
        list.flatMap { listOf(it.localPort) + it.computerPorts.values }.toSet()

    /** Adds or replaces (by [original] name). Changing host/port un-pins the server identity. */
    fun upsert(original: String?, p: Profile): String? {
        val name = p.name.trim()
        val host = p.host.trim()
        val user = p.username.trim()
        if (name.isEmpty() || host.isEmpty() || user.isEmpty() || p.port !in 1..65535) {
            return "Name, address, port and username are required"
        }
        val list = load().toMutableList()
        val idx = list.indexOfFirst { it.name == original }
        if (list.any { it.name == name } && (idx < 0 || list[idx].name != name)) {
            return "A computer with that name already exists"
        }
        var np = p.copy(
            name = name, host = host, username = user, rdpUsername = p.rdpUsername.trim(),
            computer = p.computer.trim().lowercase(), homeHost = p.homeHost.trim(),
        )
        if (idx >= 0) {
            val old = list[idx]
            np = np.copy(
                hostFingerprint = if (old.host == host && old.port == p.port) old.hostFingerprint else "",
                localPort = old.localPort,
                computerPorts = old.computerPorts,
                homeKeyAlias = old.homeKeyAlias,
                homeDevice = old.homeDevice,
            )
            list[idx] = np
        } else {
            val used = usedPorts(list)
            np = np.copy(
                hostFingerprint = "", localPort = (13389..13499).first { it !in used }, computerPorts = emptyMap(),
                homeKeyAlias = "", homeDevice = "",
            )
            list += np
        }
        save(list)
        return null
    }

    /** Deletes a saved computer (and its home key). */
    fun delete(name: String) {
        load().firstOrNull { it.name == name }?.homeKeyAlias?.takeIf { it.isNotEmpty() }?.let { DeviceKeys.delete(it) }
        save(load().filter { it.name != name })
    }

    /** Records (or with alias "" clears) this phone's trusted home login for a profile. */
    fun setHome(name: String, alias: String, device: String, homeHost: String) =
        save(load().map { if (it.name == name) it.copy(homeKeyAlias = alias, homeDevice = device, homeHost = homeHost) else it })

    fun pin(name: String, fingerprint: String) =
        save(load().map { if (it.name == name) it.copy(hostFingerprint = fingerprint) else it })

    /** Remembers [computer] as this profile's hub PC ("" = ask each time). */
    fun setComputer(name: String, computer: String) =
        save(load().map { if (it.name == name) it.copy(computer = computer) else it })

    /** The loopback port for a hub PC within a profile, assigned on first use. */
    fun portFor(name: String, computer: String): Int {
        val list = load()
        val p = list.firstOrNull { it.name == name } ?: return 13389
        p.computerPorts[computer]?.let { return it }
        val port = (13389..13499).first { it !in usedPorts(list) }
        save(list.map { if (it.name == name) it.copy(computerPorts = it.computerPorts + (computer to port)) else it })
        return port
    }

    /**
     * Lets chrome://inspect on a USB-connected PC see the in-app web pages
     * (console, network). Off by default: it's a troubleshooting aid.
     */
    var pageDebugging: Boolean
        get() = prefs.getBoolean("pageDebugging", false)
        set(v) = prefs.edit().putBoolean("pageDebugging", v).apply()

    fun links(): List<LinkConfig> {
        val arr = JSONArray(prefs.getString("links", "[]"))
        return (0 until arr.length()).map { i ->
            val o = arr.getJSONObject(i)
            LinkConfig(
                o.getString("keyAlias"), o.getString("profile"), o.getString("device"),
                o.getString("service"), o.getInt("localPort"), o.optBoolean("enabled", true),
            )
        }
    }

    fun saveLinks(list: List<LinkConfig>) {
        val arr = JSONArray()
        list.forEach {
            arr.put(
                JSONObject().put("keyAlias", it.keyAlias).put("profile", it.profile).put("device", it.device)
                    .put("service", it.service).put("localPort", it.localPort).put("enabled", it.enabled),
            )
        }
        prefs.edit().putString("links", arr.toString()).apply()
    }
}
