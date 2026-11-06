package app.securdp

import android.annotation.SuppressLint
import android.content.ContentValues
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import android.webkit.CookieManager
import android.webkit.URLUtil
import android.webkit.WebResourceResponse
import androidx.core.content.FileProvider
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.security.cert.X509Certificate
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.X509TrustManager

/**
 * Opens a connection to a tunnelled page (always 127.0.0.1) with the page's
 * cookies. [trustSelfSigned] is only set after the user accepted the page's
 * certificate, and only ever applies to the local tunnel end.
 */
fun openTunnelConnection(url: String, headers: Map<String, String>, trustSelfSigned: Boolean): HttpURLConnection {
    val u = URL(url)
    require(u.host == "127.0.0.1") { "not a tunnel address" }
    val c = u.openConnection() as HttpURLConnection
    c.connectTimeout = 15_000
    c.readTimeout = 60_000
    headers.forEach { (k, v) -> if (!k.equals("Accept-Encoding", true)) c.setRequestProperty(k, v) }
    CookieManager.getInstance().getCookie(url)?.let { c.setRequestProperty("Cookie", it) }
    if (c is HttpsURLConnection && trustSelfSigned) {
        c.sslSocketFactory = trustAll.socketFactory
        c.setHostnameVerifier { _, _ -> true }
    }
    return c
}

@SuppressLint("CustomX509TrustManager", "TrustAllX509TrustManager")
private val trustAll: SSLContext = SSLContext.getInstance("TLS").apply {
    init(null, arrayOf(object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
        override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
    }), null)
}

/** Serves a subresource the page requested from its real address, via the tunnel. */
fun tunnelResponse(url: String, headers: Map<String, String>, trustSelfSigned: Boolean): WebResourceResponse? = runCatching {
    val c = openTunnelConnection(url, headers, trustSelfSigned)
    val type = c.contentType ?: "application/octet-stream"
    val mime = type.substringBefore(';').trim()
    val charset = type.substringAfter("charset=", "").trim().ifEmpty { null }
    val code = c.responseCode
    val stream = if (code >= 400) c.errorStream else c.inputStream
    val out = mutableMapOf<String, String>()
    c.headerFields.forEach { (k, v) -> if (k != null && v.isNotEmpty()) out[k] = v.joinToString(", ") }
    WebResourceResponse(mime, charset, code, c.responseMessage?.ifEmpty { "OK" } ?: "OK", out, stream)
}.getOrNull()

/**
 * Downloads a file from a tunnelled page into the phone's Downloads/SecuRDP
 * folder (Android 10+) or the app's cache (older), returning a URI that can
 * be opened.
 */
fun downloadThroughTunnel(
    ctx: Context, url: String, userAgent: String, disposition: String?, mime: String?, trustSelfSigned: Boolean,
): Pair<String, Uri> {
    val name = URLUtil.guessFileName(url, disposition, mime)
    val c = openTunnelConnection(url, mapOf("User-Agent" to userAgent), trustSelfSigned)
    if (c.responseCode >= 400) throw Exception("The page refused the download (HTTP ${c.responseCode})")
    val type = mime?.takeIf { it.isNotBlank() } ?: c.contentType?.substringBefore(';') ?: "application/octet-stream"
    c.inputStream.use { input ->
        if (Build.VERSION.SDK_INT >= 29) {
            val values = ContentValues().apply {
                put(MediaStore.Downloads.DISPLAY_NAME, name)
                put(MediaStore.Downloads.MIME_TYPE, type)
                put(MediaStore.Downloads.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS + "/SecuRDP")
            }
            val uri = ctx.contentResolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
                ?: throw Exception("Couldn't create the download")
            ctx.contentResolver.openOutputStream(uri)!!.use { input.copyTo(it) }
            return name to uri
        }
        val dir = File(ctx.cacheDir, "open").apply { mkdirs() }
        val out = File(dir, name)
        out.outputStream().use { input.copyTo(it) }
        return name to FileProvider.getUriForFile(ctx, "app.securdp.files", out)
    }
}

/** Opens a downloaded file with whatever app handles it. */
fun openDownloaded(ctx: Context, uri: Uri, name: String) {
    val type = ctx.contentResolver.getType(uri) ?: "*/*"
    val view = Intent(Intent.ACTION_VIEW).setDataAndType(uri, type)
        .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_ACTIVITY_NEW_TASK)
    runCatching { ctx.startActivity(Intent.createChooser(view, name).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)) }
}
