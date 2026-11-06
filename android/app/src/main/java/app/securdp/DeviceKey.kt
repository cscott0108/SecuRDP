package app.securdp

import com.jcraft.jsch.Identity
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.Base64

// App-link keys: ECDSA P-256 ("ecdsa-sha2-nistp256"), the curve every Android
// Keystore supports. The private key never leaves the Keystore; JSch only
// asks for signatures through [EcdsaIdentity].

private const val ALG = "ecdsa-sha2-nistp256"

private fun ByteArrayOutputStream.sshString(b: ByteArray) {
    write(byteArrayOf((b.size ushr 24).toByte(), (b.size ushr 16).toByte(), (b.size ushr 8).toByte(), b.size.toByte()))
    write(b)
}

private fun unsigned32(n: BigInteger): ByteArray {
    val b = n.toByteArray().let { if (it.size > 32) it.copyOfRange(it.size - 32, it.size) else it }
    return ByteArray(32 - b.size) + b
}

/** The SSH public key blob (RFC 5656) for a P-256 key. */
fun sshPublicKeyBlob(pub: ECPublicKey): ByteArray = ByteArrayOutputStream().apply {
    sshString(ALG.toByteArray())
    sshString("nistp256".toByteArray())
    sshString(byteArrayOf(4) + unsigned32(pub.w.affineX) + unsigned32(pub.w.affineY))
}.toByteArray()

/** The key as one authorized_keys line, as the hub stores it. */
fun authorizedKey(pub: ECPublicKey, comment: String): String =
    "$ALG ${Base64.getEncoder().encodeToString(sshPublicKeyBlob(pub))} ${comment.replace(Regex("\\s+"), "-")}"

/** Turns a JCA (DER) ECDSA signature into the SSH form: string(alg) + string(mpint r + mpint s). */
fun derToSshSignature(der: ByteArray): ByteArray {
    // DER: 30 len 02 lenR R 02 lenS S (short-form lengths for P-256).
    var i = 2
    if (der[1].toInt() and 0x80 != 0) i += der[1].toInt() and 0x7f
    fun int(): ByteArray {
        require(der[i].toInt() == 2) { "bad signature" }
        val len = der[i + 1].toInt() and 0xff
        val v = der.copyOfRange(i + 2, i + 2 + len)
        i += 2 + len
        return v
    }
    val r = int()
    val s = int()
    val inner = ByteArrayOutputStream().apply { sshString(r); sshString(s) }.toByteArray()
    return ByteArrayOutputStream().apply { sshString(ALG.toByteArray()); sshString(inner) }.toByteArray()
}

/** A JSch identity whose signing is done elsewhere (the Keystore, or a test key). */
class EcdsaIdentity(private val pub: ECPublicKey, private val signDer: (ByteArray) -> ByteArray) : Identity {
    override fun setPassphrase(passphrase: ByteArray?) = true
    override fun getPublicKeyBlob(): ByteArray = sshPublicKeyBlob(pub)
    override fun getSignature(data: ByteArray): ByteArray = derToSshSignature(signDer(data))
    override fun getAlgName() = ALG
    override fun getName() = "securdp-app-link"
    override fun isEncrypted() = false
    override fun clear() {}
}

/** Signs with a software key (tests, and the shape the Keystore version follows). */
fun softwareIdentity(pub: ECPublicKey, priv: PrivateKey) = EcdsaIdentity(pub) { data ->
    Signature.getInstance("SHA256withECDSA").run { initSign(priv); update(data); sign() }
}

/** App-link keys in the Android Keystore, one per paired link. */
object DeviceKeys {
    private const val STORE = "AndroidKeyStore"

    private fun keyStore() = KeyStore.getInstance(STORE).apply { load(null) }

    /** Creates a non-exportable signing key under [alias] and returns its public key. */
    fun create(alias: String): ECPublicKey {
        val spec = android.security.keystore.KeyGenParameterSpec.Builder(alias, android.security.keystore.KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(android.security.keystore.KeyProperties.DIGEST_SHA256)
            .build()
        val gen = KeyPairGenerator.getInstance(android.security.keystore.KeyProperties.KEY_ALGORITHM_EC, STORE)
        gen.initialize(spec)
        return gen.generateKeyPair().public as ECPublicKey
    }

    /** The JSch identity for [alias], or null if the key is gone. */
    fun identity(alias: String): Identity? {
        val ks = keyStore()
        val priv = ks.getKey(alias, null) as? PrivateKey ?: return null
        val pub = ks.getCertificate(alias)?.publicKey as? ECPublicKey ?: return null
        return softwareIdentity(pub, priv) // the Keystore provider does the signing
    }

    fun delete(alias: String) {
        runCatching { keyStore().deleteEntry(alias) }
    }
}
