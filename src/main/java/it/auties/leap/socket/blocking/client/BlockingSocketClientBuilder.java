package it.auties.leap.socket.blocking.client;

import it.auties.leap.socket.SocketClientBuilder;
import it.auties.leap.socket.SocketProtocol;

public final class BlockingSocketClientBuilder extends SocketClientBuilder {
    private final SocketProtocol protocol;

    BlockingSocketClientBuilder(SocketProtocol protocol) {
        this.protocol = protocol;
    }
}
