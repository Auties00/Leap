package it.auties.leap.socket;

import it.auties.leap.socket.async.AsyncSocketClient;
import it.auties.leap.socket.blocking.BlockingSocketClient;

public sealed interface SocketClient extends AutoCloseable, SocketMetadataProvider permits AsyncSocketClient, BlockingSocketClient {
    static SocketClientBuilder builder() {
        return SocketClientBuilder.instance();
    }
}
