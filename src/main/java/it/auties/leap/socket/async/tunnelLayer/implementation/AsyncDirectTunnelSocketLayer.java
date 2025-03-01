package it.auties.leap.socket.async.tunnelLayer.implementation;

import it.auties.leap.socket.async.applicationLayer.AsyncSocketApplicationLayer;
import it.auties.leap.socket.async.tunnelLayer.AsyncSocketTunnelLayer;
import it.auties.leap.socket.async.tunnelLayer.AsyncSocketTunnelLayerFactory;

import java.net.InetSocketAddress;
import java.util.concurrent.CompletableFuture;

public final class AsyncDirectTunnelSocketLayer extends AsyncSocketTunnelLayer {
    private static final AsyncSocketTunnelLayerFactory FACTORY = (applicationLayer, _) -> new AsyncDirectTunnelSocketLayer(applicationLayer);

    public AsyncDirectTunnelSocketLayer(AsyncSocketApplicationLayer applicationLayer) {
        super(applicationLayer);
    }

    public static AsyncSocketTunnelLayerFactory factory() {
        return FACTORY;
    }

    @Override
    public CompletableFuture<Void> connect(InetSocketAddress address) {
        return applicationLayer.connect(address);
    }
}
