package it.auties.leap.socket;

import it.auties.leap.socket.async.client.AsyncSocketClient;
import it.auties.leap.socket.async.client.AsyncSocketClientBuilder;
import it.auties.leap.socket.blocking.client.BlockingSocketClient;
import it.auties.leap.socket.blocking.client.BlockingSocketClientBuilder;

public sealed class SocketClientBuilder permits AsyncSocketClientBuilder, BlockingSocketClientBuilder {
    private static final SocketClientBuilder INSTANCE = new SocketClientBuilder();

    protected static SocketClientBuilder instance() {
        return INSTANCE;
    }

    protected SocketClientBuilder() {

    }

    public AsyncSocketClientBuilder async(SocketProtocol protocol) {
        return AsyncSocketClient.newBuilder(protocol);
    }

    public BlockingSocketClientBuilder blocking(SocketProtocol protocol) {
        return BlockingSocketClient.newBuilder(protocol);
    }
}
