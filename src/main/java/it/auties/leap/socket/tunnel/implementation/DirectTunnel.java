package it.auties.leap.socket.tunnel.implementation;

import it.auties.leap.socket.platform.SocketPlatform;
import it.auties.leap.socket.tunnel.SocketTunnel;

import java.net.InetSocketAddress;
import java.util.concurrent.CompletableFuture;

public final class DirectTunnel extends SocketTunnel {
    public DirectTunnel(SocketPlatform<?> channel) {
        super(channel, null, null);
    }

    @Override
    public CompletableFuture<Void> connect(InetSocketAddress address) {
        return transmissionLayer.connect(address);
    }
}
