package it.auties.leap.socket.async.tunnelLayer;

import it.auties.leap.socket.SocketTunnelLayer;
import it.auties.leap.socket.async.applicationLayer.AsyncSocketApplicationLayer;

import java.net.InetSocketAddress;
import java.util.concurrent.CompletableFuture;

public non-sealed abstract class AsyncSocketTunnelLayer implements SocketTunnelLayer {
    protected final AsyncSocketApplicationLayer applicationLayer;

    protected AsyncSocketTunnelLayer(AsyncSocketApplicationLayer applicationLayer) {
        this.applicationLayer = applicationLayer;
    }

    public abstract CompletableFuture<Void> connect(InetSocketAddress address);
}
