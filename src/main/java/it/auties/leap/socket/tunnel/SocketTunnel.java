package it.auties.leap.socket.tunnel;

import it.auties.leap.socket.platform.SocketPlatform;
import it.auties.leap.socket.security.SocketSecurity;

import java.net.InetSocketAddress;
import java.net.URI;
import java.util.concurrent.CompletableFuture;

public abstract class SocketTunnel {
    protected final SocketPlatform<?> transmissionLayer;
    protected final SocketSecurity securityLayer;
    protected final URI proxy;

    protected SocketTunnel(SocketPlatform<?> transmissionLayer, SocketSecurity securityLayer, URI proxy) {
        this.transmissionLayer = transmissionLayer;
        this.securityLayer = securityLayer;
        this.proxy = proxy;
    }

    public abstract CompletableFuture<Void> connect(InetSocketAddress address);
}
