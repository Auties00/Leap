package it.auties.leap.socket.blocking.applicationLayer;

import it.auties.leap.socket.SocketApplicationLayerFactory;
import it.auties.leap.socket.blocking.transportLayer.BlockingSocketTransportLayer;
import it.auties.leap.socket.blocking.applicationLayer.implementation.BlockingPlainApplicationLayer;
import it.auties.leap.socket.blocking.applicationLayer.implementation.BlockingSecureApplicationLayer;
import it.auties.leap.tls.context.TlsConfig;

public non-sealed interface BlockingSocketApplicationLayerFactory<P> extends SocketApplicationLayerFactory<BlockingSocketTransportLayer, P> {
    static BlockingSocketApplicationLayerFactory<Void> plain() {
        return BlockingPlainApplicationLayer.factory();
    }

    static BlockingSocketApplicationLayerFactory<TlsConfig> secure() {
        return BlockingSecureApplicationLayer.factory();
    }

    @Override
    BlockingSocketApplicationLayer newApplication(BlockingSocketTransportLayer applicationLayer, P param);
}
