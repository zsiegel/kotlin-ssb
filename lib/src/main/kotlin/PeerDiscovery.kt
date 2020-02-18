import org.slf4j.LoggerFactory
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.MulticastSocket
import java.net.Socket
import java.nio.charset.StandardCharsets

/**
 *
 * Basic thread to spin up and watch for peers.
 *
 * Once found it will attempt to do a handshake with the first peer and then stop
 *
 * Used for TESTING
 *
 */
class PeerDiscoveryThread(private val socket: DatagramSocket = MulticastSocket(8008),
                          private val buffer: ByteArray = ByteArray(128),
                          private var running: Boolean = false) : Thread() {

    private val logger = LoggerFactory.getLogger(PeerDiscoveryThread::class.java)

    override fun run() {
        super.run()
        running = true
        logger.debug("Starting local discovery thread")
        while (running) {
            running = false

            val packet = DatagramPacket(buffer, buffer.size)
            socket.receive(packet)

            val messageBytes = packet.data.sliceArray(0 until packet.length)
            logger.debug("Got peer discovery message length ${packet.length}")
            val message = String(messageBytes, StandardCharsets.UTF_8)

            val peer = message.parseNetPeer()
            peer?.let {

                logger.debug("Local peer found - key: ${peer.publicKey} address: ${peer.host} port:${peer.port}")

                val keyExchange = ClientKeyExchange(it, SSB_MAIN_NETWORK)

                val clientSocket = Socket(InetAddress.getByName(peer.host), peer.port)

                //1. Client hello
                val helloMessage = keyExchange.hello()
                val helloVerified = helloMessage?.let {
                    clientSocket.getOutputStream().write(helloMessage)

                    //2. Server Hello & Shared secret derivation
                    val serverHelloBuffer = ByteArray(64)
                    clientSocket.getInputStream().read(serverHelloBuffer)
                    keyExchange.readHello(serverHelloBuffer)

                } ?: false

                if (helloVerified) {
                    val clientAuthMessage = keyExchange.auth()
                    clientAuthMessage?.let {

                        //3. Client authenticate & Shared secret derivation
                        clientSocket.getOutputStream().write(clientAuthMessage)

                        //4. Server accept
                        val serverAcceptBuffer = ByteArray(80)
                        clientSocket.getInputStream().read(serverAcceptBuffer)
                    }
                }

            }
        }
        socket.close()
    }
}