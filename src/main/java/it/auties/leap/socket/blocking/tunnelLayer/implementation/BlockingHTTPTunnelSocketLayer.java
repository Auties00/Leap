package it.auties.leap.socket.blocking.tunnelLayer.implementation;

import it.auties.leap.socket.blocking.applicationLayer.BlockingSocketApplicationLayer;
import it.auties.leap.socket.blocking.tunnelLayer.BlockingSocketTunnelLayer;
import it.auties.leap.socket.blocking.tunnelLayer.BlockingSocketTunnelLayerFactory;

import java.net.InetSocketAddress;
import java.net.URI;

public final class BlockingHTTPTunnelSocketLayer extends BlockingSocketTunnelLayer {
    private static final BlockingSocketTunnelLayerFactory FACTORY = BlockingHTTPTunnelSocketLayer::new;

    private final URI proxy;
    public BlockingHTTPTunnelSocketLayer(BlockingSocketApplicationLayer applicationLayer, URI proxy) {
        super(applicationLayer);
        this.proxy = proxy;
    }

    public static BlockingSocketTunnelLayerFactory factory() {
        return FACTORY;
    }

    @Override
    public void connect(InetSocketAddress address) {
        throw new UnsupportedOperationException();
    }
}
