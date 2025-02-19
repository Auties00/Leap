package it.auties.leap.socket.async.applicationLayer;

import it.auties.leap.socket.SocketApplicationLayer;
import it.auties.leap.socket.async.AsyncSocketIO;
import it.auties.leap.socket.async.transportLayer.AsyncSocketTransportLayer;

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
