package it.auties.leap.socket.blocking;

import it.auties.leap.socket.SocketApplicationLayer;

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
