package it.auties.leap.socket.tunnel;

import it.auties.leap.socket.implementation.SocketImplementation;
import it.auties.leap.socket.transport.SocketTransport;

import java.net.InetSocketAddress;
import java.net.URI;
import java.util.concurrent.CompletableFuture;

public abstract class SocketTunnel {
    protected final SocketImplementation implementation;
    protected final SocketTransport securityLayer;
    protected final URI proxy;

    protected SocketTunnel(SocketImplementation implementation, SocketTransport securityLayer, URI proxy) {
        this.implementation = implementation;
        this.securityLayer = securityLayer;
        this.proxy = proxy;
    }

    public abstract CompletableFuture<Void> connect(InetSocketAddress address);
}
