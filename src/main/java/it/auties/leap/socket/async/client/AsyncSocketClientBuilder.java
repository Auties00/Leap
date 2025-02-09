package it.auties.leap.socket.async.client;

import it.auties.leap.socket.SocketClientBuilder;
import it.auties.leap.socket.SocketProtocol;

public final class AsyncSocketClientBuilder extends SocketClientBuilder {
    private final SocketProtocol protocol;

    AsyncSocketClientBuilder(SocketProtocol protocol) {
        this.protocol = protocol;
    }
}
