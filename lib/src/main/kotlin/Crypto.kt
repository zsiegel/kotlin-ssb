import com.goterl.lazycode.lazysodium.LazySodiumJava
import com.goterl.lazycode.lazysodium.SodiumJava
import com.goterl.lazycode.lazysodium.interfaces.DiffieHellman
import com.goterl.lazycode.lazysodium.interfaces.Sign
import com.goterl.lazycode.lazysodium.utils.Key
import com.goterl.lazycode.lazysodium.utils.KeyPair
import org.slf4j.LoggerFactory
import java.nio.charset.StandardCharsets
import java.util.Base64
import java.util.regex.Pattern

private val lazySodium = LazySodiumJava(SodiumJava(), StandardCharsets.UTF_8)
private val netPeerPattern: Pattern = Pattern.compile("^net:(.*):(.*)~shs:(.*)$")

/**
 *
 * Parse the first lan peer in the format net:{HOST}:{PORT}~shs:{BASE64_PUBLIC_KEY}
 *
 * This needs a lot of work - currently only works with ipv4
 *
 * See https://ssbc.github.io/scuttlebutt-protocol-guide/#discovery for more info
 *
 */
internal fun String.parseNetPeer(): DiscoveredPeer? {

    val first = this.split(";")[0]
    val result = netPeerPattern.matcher(first)
    if (!result.matches()) return null

    return DiscoveredPeer(result.group(1),
                          result.group(2).toInt(),
                          Base64.getDecoder().decode(result.group(3)))
}

/**
 * Represents a peer on the network
 */
data class DiscoveredPeer(val host: String,
                          val port: Int,
                          val publicKey: ByteArray) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as DiscoveredPeer

        if (host != other.host) return false
        if (port != other.port) return false
        if (!publicKey.contentEquals(other.publicKey)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = host.hashCode()
        result = 31 * result + port
        result = 31 * result + publicKey.contentHashCode()
        return result
    }
}

/**
 *
 * Handles a key exchange as a client
 *
 * Once a peer is discovered a client will following the following steps.
 *
 * 1) Send a hello message
 * 2) Read a hello message from the server
 * 3) Send a client auth message
 * 4) Read an accept message from the server
 *
 * At the end of this exchange the client and the server will have a shared set of keys for communication
 *
 * See https://ssbc.github.io/scuttlebutt-protocol-guide/#peer-connections for more info
 *
 */
class ClientKeyExchange(private val peer: DiscoveredPeer,
                        private val appKey: ByteArray,
                        identity: KeyPair = lazySodium.cryptoSignKeypair()) {

    private val logger = LoggerFactory.getLogger("ClientKeyExchange")

    private val identityKeyPair: KeyPair = identity
    private val ephemeralKeyPair: KeyPair = lazySodium.cryptoBoxKeypair()

    var peerEphemeralPublicKey: ByteArray = ByteArray(0)
    var sharedSecret = ByteArray(0)
    var sharedSecret2 = ByteArray(0)

    fun hello(): ByteArray? {
        val tag: ByteArray = lazySodium.randomBytesBuf(32)
        val result = lazySodium.cryptoAuth(tag, ephemeralKeyPair.publicKey.asBytes, 32, appKey)
        if (!result) {
            logger.error("Unable to generate hello message")
            return null
        }

        return tag + ephemeralKeyPair.publicKey.asBytes
    }

    fun readHello(hello: ByteArray): Boolean {

        if (hello.size != 64) {
            logger.error("Invalid hello message length: ${hello.size}")
            return false
        }

        when (val result = Client.verify(hello, appKey)) {
            is Operation.Ok -> peerEphemeralPublicKey = result.data
            is Operation.Failed -> return false
        }

        when (val sharedSecretResult = Client.deriveSharedSecret(ephemeralSecret, peerEphemeralPublicKey)) {
            is Operation.Ok -> sharedSecret = sharedSecretResult.data
            is Operation.Failed -> {
                logger.error("Unable to derive shared secret")
                return false
            }
        }

        when (val sharedSecret2Result = Client.deriveSharedSecret2(ephemeralSecret, peer.publicKey)) {
            is Operation.Ok -> sharedSecret2 = sharedSecret2Result.data
            is Operation.Failed -> {
                logger.error("Unable to derive shared secret2")
                return false
            }
        }

        return true
    }

    fun auth(): ByteArray? {

        val sharedSecretSha256: ByteArray
        when (val sharedSecretHashResult = Client.sha256(sharedSecret)) {
            is Operation.Ok -> sharedSecretSha256 = sharedSecretHashResult.data
            is Operation.Failed -> {
                logger.debug("Unable to hash shared secret")
                return null
            }
        }

        val message = SSB_MAIN_NETWORK + peer.publicKey + sharedSecretSha256
        val signatureResult = Client.newDetachedSignature(message,
                                                          identityKeyPair.secretKey.asBytes)

        val detachedSignature: ByteArray
        when (signatureResult) {
            is Operation.Ok -> detachedSignature = signatureResult.data
            is Operation.Failed -> {
                logger.debug("Unable to create detached signature")
                return null
            }
        }

        val networkAndKeys = SSB_MAIN_NETWORK + sharedSecret + sharedSecret2

        val hashedKey: ByteArray
        when (val secretHashResult = Client.sha256(networkAndKeys)) {
            is Operation.Ok -> hashedKey = secretHashResult.data
            is Operation.Failed -> {
                logger.error("Unable to hash secret key")
                return null
            }
        }

        val secretMessage = detachedSignature + identityKeyPair.publicKey.asBytes

        val secretBoxResult = Client.signatureInSecretBox(secretMessage,
                                                          hashedKey)

        return when (secretBoxResult) {
            is Operation.Ok -> secretBoxResult.data
            is Operation.Failed -> {
                logger.debug("Unable to encrypt client auth message")
                null
            }
        }
    }

    private val ephemeralSecret: ByteArray
        get() {
            return ephemeralKeyPair.secretKey.asBytes
        }
}

class ServerKeyExchange(private val appKey: ByteArray) {

    fun readHello(hello: ByteArray): Boolean {
        if (hello.size != 64) {
            return false
        }

        val clientHmac = hello.slice(0 until 32).toByteArray()
        val clientEphemeralPublicKey = hello.slice(32 until 64).toByteArray()

        return lazySodium.cryptoAuthVerify(clientHmac,
                                           clientEphemeralPublicKey, clientEphemeralPublicKey.size.toLong(),
                                           appKey)
    }
}

/**
 * Represents a handshake operation - because things can fail when doing crypto :)
 */
internal sealed class Operation {
    data class Ok(val data: ByteArray) : Operation() {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false

            other as Ok

            if (!data.contentEquals(other.data)) return false

            return true
        }

        override fun hashCode(): Int {
            return data.contentHashCode()
        }
    }

    object Failed : Operation()
}

/**
 * Functions for client handshake
 */
internal object Client {

    fun verify(message: ByteArray, appKey: ByteArray): Operation {
        if (message.size != 64) {
            return Operation.Failed
        }
        val mac = message.sliceArray(0 until 32)
        val epk = message.sliceArray(32 until 64)

        val verified = lazySodium.cryptoAuthVerify(mac,
                                                   epk,
                                                   32,
                                                   appKey)
        return if (verified) {
            Operation.Ok(epk)
        } else {
            Operation.Failed
        }
    }

    fun sha256(bytes: ByteArray): Operation {
        val hash = ByteArray(32)
        val result = lazySodium.cryptoHashSha256(hash,
                                                 bytes, bytes.size.toLong())

        return if (result) {
            Operation.Ok(hash)
        } else {
            Operation.Failed
        }
    }

    fun deriveSharedSecret(esk: ByteArray, epk: ByteArray): Operation {
        val sharedKey = ByteArray(DiffieHellman.SCALARMULT_BYTES)
        val result = lazySodium.cryptoScalarMult(sharedKey, esk, epk)
        if (!result) {
            return Operation.Failed
        }
        return Operation.Ok(sharedKey)
    }

    fun deriveSharedSecret2(clientEphemeralSecretKey: ByteArray, serverIdentityPublicKey: ByteArray): Operation {
        val curve = ByteArray(Sign.CURVE25519_PUBLICKEYBYTES)
        val result = lazySodium.convertPublicKeyEd25519ToCurve25519(curve, serverIdentityPublicKey)
        if (!result) {
            return Operation.Failed
        }
        val sharedSecret = lazySodium.cryptoScalarMult(Key.fromBytes(clientEphemeralSecretKey), Key.fromBytes(curve))
        return Operation.Ok(sharedSecret.asBytes)
    }

    fun newDetachedSignature(message: ByteArray, identity: ByteArray): Operation {
        val detachedSignature = ByteArray(64)
        if (!lazySodium.cryptoSignDetached(detachedSignature,
                                           message, message.size.toLong(),
                                           identity)) {
            return Operation.Failed
        }
        return Operation.Ok(detachedSignature)
    }

    fun signatureInSecretBox(secretMessage: ByteArray,
                             hashedKey: ByteArray): Operation {

        val cipherText = ByteArray(112)
        val result = lazySodium.cryptoSecretBoxEasy(cipherText,
                                                    secretMessage, secretMessage.size.toLong(),
                                                    ByteArray(24),
                                                    hashedKey)


        return if (result) {
            Operation.Ok(cipherText)
        } else {
            Operation.Failed
        }
    }
}

/**
 * Functions for the server handshake
 */
internal object Server {

    fun deriveSharedSecret(serverIdentitySecretKey: ByteArray, clientEphemeralPublicKey: ByteArray): ByteArray {
        val curve = ByteArray(Sign.CURVE25519_PUBLICKEYBYTES)
        val result = lazySodium.convertSecretKeyEd25519ToCurve25519(curve, serverIdentitySecretKey)
        if (!result) {
            LoggerFactory.getLogger("Crypto").error("Unable to convert server serverIdentitySecretKey key to curve")
            return ByteArray(0)
        }
        val sharedSecret = lazySodium.cryptoScalarMult(Key.fromBytes(curve), Key.fromBytes(clientEphemeralPublicKey))
        return sharedSecret.asBytes
    }

}