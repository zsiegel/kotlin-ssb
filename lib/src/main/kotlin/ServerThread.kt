import com.goterl.lazycode.lazysodium.LazySodiumJava
import com.goterl.lazycode.lazysodium.SodiumJava
import org.slf4j.LoggerFactory
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.MulticastSocket
import java.net.ServerSocket
import java.nio.charset.StandardCharsets
import java.util.Base64

private val lazySodium = LazySodiumJava(SodiumJava(), StandardCharsets.UTF_8)

/**
 *
 * Basic thread to spin up and wait for peers to connect.
 *
 * Once found it will attempt to do a handshake with the first peer and then stop
 *
 * Used for TESTING
 *
 */
class ServerThread(private val socket: DatagramSocket = MulticastSocket(8009),
                   private val buffer: ByteArray = ByteArray(128),
                   private var running: Boolean = false) : Thread() {

    private val logger = LoggerFactory.getLogger(ServerThread::class.java)

    override fun run() {
        super.run()
        running = true
        logger.debug("Starting local server thread")

        val localhost = InetAddress.getByName("localhost")

        val identity = lazySodium.cryptoSignKeypair()
        val publicKeyBase64 = Base64.getEncoder().encodeToString(identity.publicKey.asBytes)
        val advertisementString = "net:${localhost.hostAddress}:8009~shs:$publicKeyBase64"
        val advertisementBytes = advertisementString.toByteArray()
        val advertisementPacket = DatagramPacket(advertisementBytes, advertisementBytes.size, localhost, 8008)
        socket.send(advertisementPacket)

        val serverSocket = ServerSocket(8009)
        while (running) {
            running = false

            val clientSocket = serverSocket.accept()

            val serverKeyExchange = ServerKeyExchange(SSB_MAIN_NETWORK)

            val length = clientSocket.getInputStream().read(buffer)
            val helloMessage = buffer.slice(0 until length).toByteArray()
            val result = serverKeyExchange.readHello(helloMessage)
            if (result) {
                logger.debug("Hello message is verified")
            } else {
                logger.error("Invalid hello message")
            }
            clientSocket.close()
        }
        serverSocket.close()
        socket.close()
    }
}