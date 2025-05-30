package it.auties.leap.socket;

import it.auties.leap.socket.async.AsyncSocketClient;
import it.auties.leap.socket.async.AsyncSocketClientBuilder;
import it.auties.leap.socket.blocking.BlockingSocketClient;
import it.auties.leap.socket.blocking.BlockingSocketClientBuilder;

public sealed class SocketClientBuilder permits AsyncSocketClientBuilder, BlockingSocketClientBuilder {
    private static final SocketClientBuilder INSTANCE = new SocketClientBuilder();

    protected static SocketClientBuilder instance() {
        return INSTANCE;
    }

    protected SocketClientBuilder() {

    }

    public AsyncSocketClientBuilder async(SocketProtocol protocol) {
        return AsyncSocketClient.builder(protocol);
    }

    public BlockingSocketClientBuilder blocking(SocketProtocol protocol) {
        return BlockingSocketClient.builder(protocol);
    }
}