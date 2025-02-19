package it.auties.leap.socket.blocking.tunnelLayer;

import it.auties.leap.socket.SocketTunnelLayer;
import it.auties.leap.socket.blocking.applicationLayer.BlockingSocketApplicationLayer;

import java.net.InetSocketAddress;

public non-sealed abstract class BlockingSocketTunnelLayer implements SocketTunnelLayer {
    protected final BlockingSocketApplicationLayer applicationLayer;
    protected BlockingSocketTunnelLayer(BlockingSocketApplicationLayer applicationLayer) {
        this.applicationLayer = applicationLayer;
    }

    public abstract void connect(InetSocketAddress address);
}
