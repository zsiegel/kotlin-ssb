//Used for testing
fun main(args: Array<String>) {

    val clientThread = PeerDiscoveryThread()
    val serverThread = ServerThread()

    serverThread.start()
    clientThread.start()
    clientThread.join()
    serverThread.join()
}