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
)

class ProfileStore(context: Context) {
    private val prefs = context.getSharedPreferences("profiles", Context.MODE_PRIVATE)

    fun load(): List<Profile> {
        val arr = JSONArray(prefs.getString("list", "[]"))
        return (0 until arr.length()).map { i ->
            val o = arr.getJSONObject(i)
            Profile(
                name = o.getString("name"),
                host = o.getString("host"),
                port = o.getInt("port"),
                username = o.getString("username"),
                rdpUsername = o.optString("rdpUsername"),
                hostFingerprint = o.optString("hostFingerprint"),
                localPort = o.optInt("localPort"),
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
            })
        }
        prefs.edit().putString("list", arr.toString()).apply()
    }

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
        var np = p.copy(name = name, host = host, username = user, rdpUsername = p.rdpUsername.trim())
        if (idx >= 0) {
            val old = list[idx]
            np = np.copy(
                hostFingerprint = if (old.host == host && old.port == p.port) old.hostFingerprint else "",
                localPort = old.localPort,
            )
            list[idx] = np
        } else {
            val used = list.map { it.localPort }.toSet()
            np = np.copy(hostFingerprint = "", localPort = (13389..13499).first { it !in used })
            list += np
        }
        save(list)
        return null
    }

    fun delete(name: String) = save(load().filter { it.name != name })

    fun pin(name: String, fingerprint: String) =
        save(load().map { if (it.name == name) it.copy(hostFingerprint = fingerprint) else it })
}
