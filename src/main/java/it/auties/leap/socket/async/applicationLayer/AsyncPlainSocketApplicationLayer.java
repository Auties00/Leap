package it.auties.leap.socket.async.applicationLayer;

import it.auties.leap.socket.async.AsyncSocketApplicationLayer;
import it.auties.leap.socket.async.AsyncSocketApplicationLayerFactory;
import it.auties.leap.socket.async.AsyncSocketTransportLayer;

import java.nio.ByteBuffer;
import java.util.concurrent.CompletableFuture;

public class AsyncPlainSocketApplicationLayer extends AsyncSocketApplicationLayer {
    private static final AsyncSocketApplicationLayerFactory<Void> FACTORY = (transportLayer, _) -> new AsyncPlainSocketApplicationLayer(transportLayer);

    public AsyncPlainSocketApplicationLayer(AsyncSocketTransportLayer transportLayer) {
        super(transportLayer);
    }

    public static AsyncSocketApplicationLayerFactory<Void> factory() {
        return FACTORY;
    }

    @Override
    public CompletableFuture<Void> handshake() {
        return CompletableFuture.completedFuture(null);
    }

    @Override
    public CompletableFuture<Void> write(ByteBuffer buffer) {
        return transportLayer.write(buffer);
    }

    @Override
    public CompletableFuture<Void> read(ByteBuffer buffer) {
        return transportLayer.read(buffer);
    }

    @Override
    public CompletableFuture<Void> readFully(ByteBuffer buffer) {
        return transportLayer.readFully(buffer);
    }
}
