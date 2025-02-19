package it.auties.leap.socket.async.applicationLayer;

import it.auties.leap.socket.SocketApplicationLayerFactory;
import it.auties.leap.socket.async.transportLayer.AsyncSocketTransportLayer;
import it.auties.leap.socket.async.applicationLayer.implementation.AsyncPlainSocketApplicationLayer;
import it.auties.leap.socket.async.applicationLayer.implementation.AsyncSecureSocketApplicationLayer;
import it.auties.leap.tls.context.TlsConfig;

public non-sealed interface AsyncSocketApplicationLayerFactory<P> extends SocketApplicationLayerFactory<AsyncSocketTransportLayer, P> {
    static AsyncSocketApplicationLayerFactory<Void> plain() {
        return AsyncPlainSocketApplicationLayer.factory();
    }

    static AsyncSocketApplicationLayerFactory<TlsConfig> secure() {
        return AsyncSecureSocketApplicationLayer.factory();
    }

    @Override
    AsyncSocketApplicationLayer newApplication(AsyncSocketTransportLayer applicationLayer, P param);
}
