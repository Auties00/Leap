package it.auties.leap.socket.blocking;

import it.auties.leap.socket.SocketTunnelLayer;

import java.net.InetSocketAddress;

public non-sealed abstract class BlockingSocketTunnelLayer implements SocketTunnelLayer {
    protected final BlockingSocketApplicationLayer applicationLayer;
    protected BlockingSocketTunnelLayer(BlockingSocketApplicationLayer applicationLayer) {
        this.applicationLayer = applicationLayer;
    }

    public abstract void connect(InetSocketAddress address);
}
