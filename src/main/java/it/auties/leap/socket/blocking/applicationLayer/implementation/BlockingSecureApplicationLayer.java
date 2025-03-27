package it.auties.leap.socket.blocking.applicationLayer.implementation;

import it.auties.leap.socket.blocking.applicationLayer.BlockingSocketApplicationLayer;
import it.auties.leap.socket.blocking.applicationLayer.BlockingSocketApplicationLayerFactory;
import it.auties.leap.socket.blocking.transportLayer.BlockingSocketTransportLayer;
import it.auties.leap.tls.context.TlsContext;

import java.io.IOException;
import java.nio.ByteBuffer;

public class BlockingSecureApplicationLayer extends BlockingSocketApplicationLayer {
    private static final BlockingSocketApplicationLayerFactory<TlsContext> FACTORY = BlockingSecureApplicationLayer::new;

    private final TlsContext context;

    public BlockingSecureApplicationLayer(BlockingSocketTransportLayer transportLayer, TlsContext context) {
        super(transportLayer);
        this.context = context;
    }

    public static BlockingSocketApplicationLayerFactory<TlsContext> factory() {
        return FACTORY;
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

    @Override
    public void close(boolean error) throws IOException {
        transportLayer.close();
    }
}
