package it.auties.leap.socket.blocking.client;

import it.auties.leap.socket.SocketClientTunnel;

import java.net.InetSocketAddress;

public non-sealed abstract class BlockingSocketClientTunnel implements SocketClientTunnel {
    protected final BlockingSocketClient applicationDelegate;
    protected BlockingSocketClientTunnel(BlockingSocketClient applicationDelegate) {
        this.applicationDelegate = applicationDelegate;
    }

    public abstract void connect(InetSocketAddress address);
}
