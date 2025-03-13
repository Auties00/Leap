package it.auties.leap.socket.async.tunnelLayer.implementation;

import it.auties.leap.socket.async.applicationLayer.AsyncSocketApplicationLayer;
import it.auties.leap.socket.async.tunnelLayer.AsyncSocketTunnelLayer;
import it.auties.leap.socket.async.tunnelLayer.AsyncSocketTunnelLayerFactory;

import java.net.InetSocketAddress;
import java.net.URI;
import java.util.concurrent.CompletableFuture;

public final class AsyncHTTPTunnelSocketLayer extends AsyncSocketTunnelLayer {
    private static final AsyncSocketTunnelLayerFactory FACTORY = AsyncHTTPTunnelSocketLayer::new;

    private final URI proxy;
    public AsyncHTTPTunnelSocketLayer(AsyncSocketApplicationLayer applicationLayer, URI proxy) {
        super(applicationLayer);
        this.proxy = proxy;
    }

    public static AsyncSocketTunnelLayerFactory factory() {
        return FACTORY;
    }

    @Override
    public CompletableFuture<Void> connect(InetSocketAddress address) {
        throw new UnsupportedOperationException();
    }
}
