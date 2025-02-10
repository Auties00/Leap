package it.auties.leap.socket.async;

import it.auties.leap.socket.SocketApplicationLayer;

import java.util.concurrent.CompletableFuture;

public non-sealed abstract class AsyncSocketApplicationLayer implements SocketApplicationLayer, AsyncSocketIO {
    protected final AsyncSocketTransportLayer transportLayer;

    public AsyncSocketApplicationLayer(AsyncSocketTransportLayer transportLayer) {
        this.transportLayer = transportLayer;
    }

    @Override
    public AsyncSocketTransportLayer transportLayer() {
        return transportLayer;
    }

    public abstract CompletableFuture<Void> handshake();
}
