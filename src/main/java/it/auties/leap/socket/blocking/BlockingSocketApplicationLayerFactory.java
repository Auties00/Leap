package it.auties.leap.socket.blocking;

import it.auties.leap.socket.SocketApplicationLayerFactory;
import it.auties.leap.socket.blocking.applicationLayer.BlockingPlainApplicationLayer;
import it.auties.leap.socket.blocking.applicationLayer.BlockingSecureApplicationLayer;
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
