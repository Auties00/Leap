package it.auties.leap.socket.blocking.applicationLayer;

import it.auties.leap.socket.blocking.BlockingSocketApplicationLayer;
import it.auties.leap.socket.blocking.BlockingSocketTransportLayer;

import java.nio.ByteBuffer;

public class BlockingPlainApplicationLayer extends BlockingSocketApplicationLayer {
    public BlockingPlainApplicationLayer(BlockingSocketTransportLayer transportLayer) {
        super(transportLayer);
    }

    @Override
    public void handshake() {

    }

    @Override
    public void write(ByteBuffer buffer) {
        transportLayer.write(buffer);
    }

    @Override
    public void read(ByteBuffer buffer) {
        transportLayer.read(buffer);
    }

    @Override
    public void readFully(ByteBuffer buffer) {
        transportLayer.readFully(buffer);
    }
}
