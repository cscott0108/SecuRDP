package app.securdp

import android.os.Build
import android.widget.Toast
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import java.util.UUID
import kotlin.concurrent.thread

// App links UI: pairing (from a hub login) and the list on the main screen.

/** The loopback port suggested for a page: its own port when usable, so apps can use the same number at home. */
fun suggestedLinkPort(service: HubService, taken: Set<Int>): Int {
    val own = service.target.substringAfterLast(':', "").toIntOrNull()
    if (own != null && own in 1024..65535 && own !in taken) return own
    return (18100..18199).first { it !in taken }
}

/** Pairs this phone with [service] on the connected hub and saves the link. */
@Composable
fun PairLinkDialog(profile: Profile, service: HubService, store: ProfileStore, onDone: () -> Unit) {
    val ctx = LocalContext.current
    val taken = remember { store.links().map { it.localPort }.toSet() }
    var device by remember { mutableStateOf(Build.MODEL ?: "Phone") }
    var port by remember { mutableStateOf(suggestedLinkPort(service, taken).toString()) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    val main = remember { android.os.Handler(android.os.Looper.getMainLooper()) }

    fun pair() {
        val p = port.toIntOrNull()
        if (p == null || p !in 1024..65535) { error = "Port must be 1024-65535"; return }
        if (p in taken) { error = "Another app link already uses port $p"; return }
        val name = device.trim()
        if (name.isEmpty() || name.length > 40) { error = "Give this phone a name (up to 40 characters)"; return }
        busy = true
        error = null
        thread(name = "securdp-pair") {
            val alias = "link-" + UUID.randomUUID()
            try {
                val t = TunnelManager.tunnel ?: throw Exception("Not connected to the hub")
                val pub = DeviceKeys.create(alias)
                t.pair(name, service.name, authorizedKey(pub, "SecuRDP-$name"))
                // Pairing again under the same name replaces the old link (and key) on both sides.
                val old = store.links().filter { it.profile == profile.name && it.device.equals(name, true) }
                old.forEach { DeviceKeys.delete(it.keyAlias) }
                store.saveLinks(store.links() - old.toSet() + LinkConfig(alias, profile.name, name, service.name, p))
                LinkManager.refresh(ctx)
                main.post {
                    Toast.makeText(ctx, "Linked: apps on this phone reach ${service.name} at 127.0.0.1:$p", Toast.LENGTH_LONG).show()
                    onDone()
                }
            } catch (e: Exception) {
                DeviceKeys.delete(alias)
                main.post { busy = false; error = e.message ?: "Pairing failed" }
            }
        }
    }

    AlertDialog(
        onDismissRequest = { if (!busy) onDone() },
        title = { Text("Link an app to ${service.name}") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    "Apps on this phone will reach ${service.name} at 127.0.0.1:<port>, without your password or code, " +
                        "using a key kept in this phone's secure storage. The link reaches only this page. " +
                        "The tunnel opens only while an app is using it.",
                    style = MaterialTheme.typography.bodySmall,
                )
                OutlinedTextField(device, { device = it }, label = { Text("This phone's name (shown on the hub)") }, singleLine = true)
                OutlinedTextField(
                    port, { port = it.filter(Char::isDigit) }, label = { Text("Port on this phone") }, singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                )
                error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
            }
        },
        confirmButton = { TextButton(onClick = ::pair, enabled = !busy) { Text(if (busy) "Pairing…" else "Pair") } },
        dismissButton = { TextButton(onClick = onDone, enabled = !busy) { Text("Cancel") } },
    )
}

/** One saved app link on the main screen: on/off, status, remove. */
@Composable
fun LinkCard(link: LinkConfig, status: String?, store: ProfileStore, onChanged: () -> Unit) {
    val ctx = LocalContext.current
    var confirm by remember { mutableStateOf(false) }
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text("🔗 ${link.service} → 127.0.0.1:${link.localPort}", fontWeight = FontWeight.SemiBold)
                    Text(
                        "via ${link.profile} · paired as \"${link.device}\"",
                        style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Switch(checked = link.enabled, onCheckedChange = { on ->
                    store.saveLinks(store.links().map { if (it.keyAlias == link.keyAlias) it.copy(enabled = on) else it })
                    LinkManager.refresh(ctx)
                    onChanged()
                })
            }
            val text = when {
                !link.enabled -> "Off"
                status == null -> "Starting…"
                status == "Ready" -> "Ready - connects when an app uses it"
                status == "Connected" -> "Connected"
                else -> status
            }
            val ok = status == "Ready" || status == "Connected" || !link.enabled
            Text(text, style = MaterialTheme.typography.bodySmall, color = if (ok) MaterialTheme.colorScheme.onSurfaceVariant else MaterialTheme.colorScheme.error)
            TextButton(onClick = { confirm = true }) { Text("Remove", color = MaterialTheme.colorScheme.error) }
        }
    }
    if (confirm) {
        AlertDialog(
            onDismissRequest = { confirm = false },
            title = { Text("Remove this app link?") },
            text = {
                Text(
                    "The key is deleted from this phone, so the link stops working. " +
                        "Also remove \"${link.device}\" on the hub (Users tab), or connect to the hub first and it's removed there too.",
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    confirm = false
                    thread(name = "securdp-unpair") {
                        // Connected to that hub with a full login? Remove it there as well.
                        val st = TunnelManager.state.value
                        val hubProfile = (st as? TunnelState.Hub)?.profile?.name ?: (st as? TunnelState.Connected)?.profile?.name
                        if (hubProfile == link.profile) runCatching { TunnelManager.tunnel?.unpair(link.device) }
                        DeviceKeys.delete(link.keyAlias)
                        store.saveLinks(store.links().filter { it.keyAlias != link.keyAlias })
                        LinkManager.refresh(ctx)
                        android.os.Handler(android.os.Looper.getMainLooper()).post(onChanged)
                    }
                }) { Text("Remove") }
            },
            dismissButton = { TextButton(onClick = { confirm = false }) { Text("Cancel") } },
        )
    }
}
