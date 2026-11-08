package app.securdp

import android.widget.Toast
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle

// Switch to remote (leaving a Local login) and reconnecting after the network
// dropped: both log in with password + code and keep everything open.

/** Shown while connected locally, or while a dropped connection waits to come back. */
@Composable
fun LoginModeBanner() {
    val mode by TunnelManager.login.collectAsStateWithLifecycle()
    if (!mode.home && !mode.lost) return
    var ask by remember { mutableStateOf(false) }
    val colors = if (mode.lost) CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer) else CardDefaults.cardColors()
    Card(Modifier.fillMaxWidth(), colors = colors) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            when {
                mode.lost && mode.home -> {
                    Text("Connection lost", fontWeight = FontWeight.SemiBold)
                    Text(
                        "It reconnects by itself when you're back on your home network. Away from home, continue " +
                            "with your password and code. Remote Desktop and open pages carry on. Otherwise it closes after 5 minutes.",
                        style = MaterialTheme.typography.bodySmall,
                    )
                    Button(onClick = { ask = true }) { Text("Continue remotely") }
                }
                mode.lost -> {
                    Text("Connection lost", fontWeight = FontWeight.SemiBold)
                    Text(
                        "The network changed. Enter your password and code to reconnect - Remote Desktop and open pages " +
                            "carry on. Otherwise it closes after 5 minutes.",
                        style = MaterialTheme.typography.bodySmall,
                    )
                    Button(onClick = { ask = true }) { Text("Reconnect") }
                }
                else -> {
                    Text("Connected locally (home network)", fontWeight = FontWeight.SemiBold)
                    Text(
                        "Leaving home? Switch to remote first: it logs in with your password and code through your public " +
                            "address, keeping Remote Desktop and open pages.",
                        style = MaterialTheme.typography.bodySmall,
                    )
                    OutlinedButton(onClick = { ask = true }) { Text("Switch to remote") }
                }
            }
        }
    }
    if (ask) SwitchRemoteDialog(reconnect = mode.lost, onDone = { ask = false })
}

@Composable
private fun SwitchRemoteDialog(reconnect: Boolean, onDone: () -> Unit) {
    val ctx = LocalContext.current
    var password by remember { mutableStateOf("") }
    var code by remember { mutableStateOf("") }
    var show by remember { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    val ready = password.isNotEmpty() && code.length == 6 && !busy

    fun go() {
        busy = true
        error = null
        TunnelManager.switchRemote(password, code) { err ->
            if (err == null) {
                Toast.makeText(ctx, if (reconnect) "Reconnected" else "Switched to remote", Toast.LENGTH_SHORT).show()
                onDone()
            } else {
                busy = false
                error = err
            }
        }
    }

    AlertDialog(
        onDismissRequest = { if (!busy) onDone() },
        title = { Text(if (reconnect) "Reconnect" else "Switch to remote") },
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
                error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
            }
        },
        confirmButton = {
            TextButton(onClick = ::go, enabled = ready) {
                Text(if (busy) "Logging in…" else if (reconnect) "Reconnect" else "Switch")
            }
        },
        dismissButton = { TextButton(onClick = onDone, enabled = !busy) { Text("Cancel") } },
    )
}
