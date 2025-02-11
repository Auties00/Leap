package it.auties.leap.socket.blocking.applicationLayer;

import it.auties.leap.socket.blocking.BlockingSocketApplicationLayer;
import it.auties.leap.socket.blocking.BlockingSocketApplicationLayerFactory;
import it.auties.leap.socket.blocking.BlockingSocketTransportLayer;
import it.auties.leap.tls.TlsConfig;

import java.nio.ByteBuffer;

public class BlockingSecureApplicationLayer extends BlockingSocketApplicationLayer {
    private static final BlockingSocketApplicationLayerFactory<TlsConfig> FACTORY = BlockingSecureApplicationLayer::new;

    private final TlsConfig config;

    public BlockingSecureApplicationLayer(BlockingSocketTransportLayer transportLayer, TlsConfig config) {
        super(transportLayer);
        this.config = config;
    }

    public static BlockingSocketApplicationLayerFactory<TlsConfig> factory() {
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
}
