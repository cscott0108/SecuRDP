package app.securdp

import android.Manifest
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        val store = ProfileStore(this)
        setContent { SecuRDPTheme { MainScreen(store) } }
    }
}

private val Blue = Color(0xFF2563EB)
private val Good = Color(0xFF16A34A)

@Composable
fun SecuRDPTheme(content: @Composable () -> Unit) {
    val scheme = if (isSystemInDarkTheme()) {
        darkColorScheme(primary = Color(0xFF3B82F6), background = Color(0xFF0F172A), surface = Color(0xFF0F172A))
    } else {
        lightColorScheme(primary = Blue)
    }
    MaterialTheme(colorScheme = scheme, content = content)
}

private data class Creds(val password: String, val code: String)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MainScreen(store: ProfileStore) {
    val context = LocalContext.current
    var profiles by remember { mutableStateOf(store.load()) }
    val state by TunnelManager.state.collectAsStateWithLifecycle()

    var editing by remember { mutableStateOf<Profile?>(null) }
    var adding by remember { mutableStateOf(false) }
    var connectTo by remember { mutableStateOf<Profile?>(null) }
    // Held in memory only while a first-connect fingerprint check is pending.
    var creds by remember { mutableStateOf<Creds?>(null) }
    var openWhenConnected by remember { mutableStateOf(false) }

    val notifPermission = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) {}
    LaunchedEffect(Unit) {
        if (Build.VERSION.SDK_INT >= 33) notifPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
    }

    // Open Remote Desktop as soon as the tunnel is up (from the visible activity).
    LaunchedEffect(state) {
        val s = state
        if (s is TunnelState.Connected && openWhenConnected) {
            openWhenConnected = false
            creds = null
            openRemoteDesktop(context, s.profile)
        }
        if (s is TunnelState.Failed) creds = null
    }

    Scaffold(
        topBar = { TopAppBar(title = { Text("SecuRDP", fontWeight = FontWeight.SemiBold) }) },
        floatingActionButton = {
            ExtendedFloatingActionButton(onClick = { adding = true }) { Text("+ Add computer") }
        },
    ) { pad ->
        LazyColumn(
            modifier = Modifier.fillMaxSize().padding(pad),
            contentPadding = PaddingValues(16.dp, 8.dp, 16.dp, 96.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            item { StatusCard(state, context) }
            if (profiles.isEmpty()) {
                item {
                    Text(
                        "No saved computers yet. Tap \"Add computer\" and enter your home address, " +
                            "the SecuRDP gate port and your SecuRDP username.",
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
            items(profiles, key = { it.name }) { p ->
                val busy = state is TunnelState.Connecting || state is TunnelState.Connected ||
                    state is TunnelState.NeedsChoice
                ProfileCard(
                    p, busy,
                    onConnect = { connectTo = p },
                    onEdit = { editing = p },
                    onDelete = { store.delete(p.name); profiles = store.load() },
                )
            }
            item {
                Text(
                    "Your gate password and authenticator code are asked every time and never stored. " +
                        "Remote Desktop opens automatically through the encrypted tunnel; the tunnel closes " +
                        "2 minutes after you leave Remote Desktop, or tap Disconnect in the notification.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }

    if (adding || editing != null) {
        ProfileDialog(
            initial = editing,
            onSave = { p ->
                val err = store.upsert(editing?.name, p)
                if (err == null) { profiles = store.load(); adding = false; editing = null }
                err
            },
            onDismiss = { adding = false; editing = null },
        )
    }

    connectTo?.let { p ->
        ConnectDialog(
            profile = p,
            onConnect = { pw, code ->
                connectTo = null
                creds = Creds(pw, code)
                openWhenConnected = true
                TunnelManager.connect(context, p, pw, code)
            },
            onDismiss = { connectTo = null },
        )
    }

    when (val s = state) {
        is TunnelState.NeedsTrust -> TrustDialog(
            fingerprint = s.fingerprint,
            onTrust = {
                store.pin(s.profile.name, s.fingerprint)
                profiles = store.load()
                val c = creds
                TunnelManager.clearMessage()
                val pinned = profiles.firstOrNull { it.name == s.profile.name }
                if (c != null && pinned != null) {
                    openWhenConnected = true
                    TunnelManager.connect(context, pinned, c.password, c.code)
                }
            },
            onCancel = { creds = null; TunnelManager.clearMessage() },
        )
        is TunnelState.NeedsChoice -> PickerDialog(
            computers = s.computers,
            onPick = { name, remember ->
                if (remember) profiles = store.load().map { if (it.name == s.profile.name) it.copy(computer = name) else it }
                TunnelManager.choose(context, name, remember)
            },
            onCancel = { openWhenConnected = false; TunnelManager.choose(context, null, false) },
        )
        is TunnelState.Failed -> AlertDialog(
            onDismissRequest = { TunnelManager.clearMessage() },
            confirmButton = { TextButton(onClick = { TunnelManager.clearMessage() }) { Text("OK") } },
            title = { Text("Not connected") },
            text = { Text(s.message) },
        )
        else -> {}
    }
}

@Composable
private fun StatusCard(state: TunnelState, context: android.content.Context) {
    when (state) {
        is TunnelState.Connecting -> Card(Modifier.fillMaxWidth()) {
            Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
                CircularProgressIndicator(Modifier.width(24.dp))
                Spacer(Modifier.width(12.dp))
                Text("Connecting to ${state.profile.name}…")
            }
        }
        is TunnelState.Connected -> Card(
            Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = Good.copy(alpha = 0.15f)),
        ) {
            Column(Modifier.padding(16.dp)) {
                Text(
                    "Connected to ${state.profile.name}" + (state.computer?.let { " → $it" } ?: ""),
                    fontWeight = FontWeight.SemiBold, color = Good,
                )
                Text(
                    if (state.active > 0) "Remote Desktop session active" else "Tunnel open, waiting for Remote Desktop",
                    style = MaterialTheme.typography.bodyMedium,
                )
                Text(
                    "In Remote Desktop this PC is 127.0.0.1:${state.profile.localPort}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Row(Modifier.padding(top = 12.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(onClick = { openRemoteDesktop(context, state.profile) }) { Text("Open Remote Desktop") }
                    OutlinedButton(onClick = { TunnelManager.disconnect() }) { Text("Disconnect") }
                }
            }
        }
        else -> {}
    }
}

@Composable
private fun ProfileCard(p: Profile, busy: Boolean, onConnect: () -> Unit, onEdit: () -> Unit, onDelete: () -> Unit) {
    var confirmDelete by remember { mutableStateOf(false) }
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp)) {
            Text(p.name, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
            Text(
                "${p.host}:${p.port} · gate user ${p.username}" +
                    (if (p.computer.isNotEmpty()) " · always ${p.computer}" else "") +
                    (if (p.rdpUsername.isNotEmpty()) " · Windows user ${p.rdpUsername}" else ""),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(
                if (p.hostFingerprint.isNotEmpty()) "Identity verified" else "Not yet verified",
                style = MaterialTheme.typography.bodySmall,
                color = if (p.hostFingerprint.isNotEmpty()) Good else MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Row(Modifier.padding(top = 8.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = onConnect, enabled = !busy) { Text("Connect") }
                TextButton(onClick = onEdit, enabled = !busy) { Text("Edit") }
                TextButton(onClick = { confirmDelete = true }, enabled = !busy) {
                    Text("Delete", color = MaterialTheme.colorScheme.error)
                }
            }
        }
    }
    if (confirmDelete) {
        AlertDialog(
            onDismissRequest = { confirmDelete = false },
            confirmButton = { TextButton(onClick = { confirmDelete = false; onDelete() }) { Text("Delete") } },
            dismissButton = { TextButton(onClick = { confirmDelete = false }) { Text("Cancel") } },
            title = { Text("Delete ${p.name}?") },
        )
    }
}

@Composable
private fun ProfileDialog(initial: Profile?, onSave: (Profile) -> String?, onDismiss: () -> Unit) {
    var name by remember { mutableStateOf(initial?.name ?: "") }
    var host by remember { mutableStateOf(initial?.host ?: "") }
    var port by remember { mutableStateOf(initial?.port?.toString() ?: "") }
    var user by remember { mutableStateOf(initial?.username ?: "") }
    var rdpUser by remember { mutableStateOf(initial?.rdpUsername ?: "") }
    var computer by remember { mutableStateOf(initial?.computer ?: "") }
    var error by remember { mutableStateOf<String?>(null) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(if (initial == null) "Add computer" else "Edit ${initial.name}") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(name, { name = it }, label = { Text("Name") }, singleLine = true)
                OutlinedTextField(
                    host, { host = it }, label = { Text("Address (public IP or hostname)") }, singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                )
                OutlinedTextField(
                    port, { port = it.filter(Char::isDigit).take(5) }, label = { Text("Gate port") }, singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                )
                OutlinedTextField(user, { user = it }, label = { Text("SecuRDP username") }, singleLine = true)
                OutlinedTextField(rdpUser, { rdpUser = it }, label = { Text("Windows username (optional)") }, singleLine = true)
                OutlinedTextField(
                    computer, { computer = it.lowercase().filter { c -> c.isLetterOrDigit() || c == '-' } },
                    label = { Text("Hub computer (optional)") }, singleLine = true,
                    supportingText = { Text("Blank = pick from a list each time") },
                )
                error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
            }
        },
        confirmButton = {
            TextButton(onClick = {
                error = onSave(
                    Profile(name, host, port.toIntOrNull() ?: 0, user, rdpUser,
                        initial?.hostFingerprint ?: "", initial?.localPort ?: 0, computer),
                )
            }) { Text("Save") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

@Composable
private fun ConnectDialog(profile: Profile, onConnect: (String, String) -> Unit, onDismiss: () -> Unit) {
    var password by remember { mutableStateOf("") }
    var code by remember { mutableStateOf("") }
    var show by remember { mutableStateOf(false) }
    val ready = password.isNotEmpty() && code.length == 6

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Connect to ${profile.name}") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(
                    password, { password = it }, label = { Text("Gate password") }, singleLine = true,
                    visualTransformation = if (show) VisualTransformation.None else PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                    trailingIcon = { TextButton(onClick = { show = !show }) { Text(if (show) "Hide" else "Show") } },
                )
                OutlinedTextField(
                    code, { code = it.filter(Char::isDigit).take(6) }, label = { Text("Authenticator code") },
                    singleLine = true, keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                    supportingText = { Text("${code.length}/6 - from Google Authenticator") },
                )
            }
        },
        confirmButton = { TextButton(onClick = { onConnect(password, code) }, enabled = ready) { Text("Connect") } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

@Composable
private fun PickerDialog(computers: List<HubComputer>, onPick: (String, Boolean) -> Unit, onCancel: () -> Unit) {
    var keep by remember { mutableStateOf(false) }
    AlertDialog(
        onDismissRequest = onCancel,
        title = { Text("Which computer?") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                computers.forEach { c ->
                    OutlinedButton(onClick = { onPick(c.name, keep) }, modifier = Modifier.fillMaxWidth()) {
                        Text("●", color = if (c.online) Good else MaterialTheme.colorScheme.outline)
                        Spacer(Modifier.width(10.dp))
                        Text(c.name, fontWeight = FontWeight.SemiBold, modifier = Modifier.weight(1f))
                        Text(
                            (if (c.online) "online" else "not answering") + (if (c.isDefault) " · default" else ""),
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(checked = keep, onCheckedChange = { keep = it })
                    Text("Always use this computer for this entry", style = MaterialTheme.typography.bodySmall)
                }
            }
        },
        confirmButton = {},
        dismissButton = { TextButton(onClick = onCancel) { Text("Cancel") } },
    )
}

@Composable
private fun TrustDialog(fingerprint: String, onTrust: () -> Unit, onCancel: () -> Unit) {
    AlertDialog(
        onDismissRequest = onCancel,
        title = { Text("First connection to this computer") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Compare this fingerprint with the one on that PC's \"This PC\" tab in SecuRDP:")
                Text(fingerprint, fontFamily = FontFamily.Monospace, fontWeight = FontWeight.SemiBold)
                Text(
                    "You only do this once. SecuRDP refuses to connect if it ever changes.",
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        },
        confirmButton = { TextButton(onClick = onTrust) { Text("They match - connect") } },
        dismissButton = { TextButton(onClick = onCancel) { Text("Cancel") } },
    )
}
