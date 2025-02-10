package it.auties.leap.socket.blocking.tunnelLayer;

import it.auties.leap.socket.blocking.BlockingSocketApplicationLayer;
import it.auties.leap.socket.blocking.BlockingSocketTunnelLayer;
import it.auties.leap.socket.blocking.BlockingSocketTunnelLayerFactory;

import java.net.InetSocketAddress;

public final class BlockingDirectTunnelSocketLayer extends BlockingSocketTunnelLayer {
    private static final BlockingSocketTunnelLayerFactory FACTORY = (applicationLayer, _) -> new BlockingDirectTunnelSocketLayer(applicationLayer);

    public BlockingDirectTunnelSocketLayer(BlockingSocketApplicationLayer applicationLayer) {
        super(applicationLayer);
    }

    public static BlockingSocketTunnelLayerFactory factory() {
        return FACTORY;
    }

    @Override
    public void connect(InetSocketAddress address) {
        applicationLayer.transportLayer()
                .connect(address);
    }
}
