package it.auties.leap.socket.async.client;

import it.auties.leap.socket.SocketClientTunnel;

import java.net.InetSocketAddress;
import java.util.concurrent.CompletableFuture;

public non-sealed abstract class AsyncSocketClientTunnel implements SocketClientTunnel {
    protected final AsyncSocketClient client;

    protected AsyncSocketClientTunnel(AsyncSocketClient client) {
        this.client = client;
    }

    public abstract CompletableFuture<Void> connect(InetSocketAddress address);
}
