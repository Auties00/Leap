package it.auties.leap.socket.blocking.applicationLayer;

import it.auties.leap.socket.SocketApplicationLayer;
import it.auties.leap.socket.blocking.BlockingSocketIO;
import it.auties.leap.socket.blocking.transportLayer.BlockingSocketTransportLayer;

public non-sealed abstract class BlockingSocketApplicationLayer implements SocketApplicationLayer, BlockingSocketIO {
    protected final BlockingSocketTransportLayer transportLayer;

    public BlockingSocketApplicationLayer(BlockingSocketTransportLayer transportLayer) {
        this.transportLayer = transportLayer;
    }

    @Override
    public BlockingSocketTransportLayer transportLayer() {
        return transportLayer;
    }

    public abstract void handshake();
}
