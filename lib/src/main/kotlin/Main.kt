//Used for testing
fun main(args: Array<String>) {

    val lanDiscovery = PeerDiscoveryThread()
    lanDiscovery.start()
    lanDiscovery.join()

}