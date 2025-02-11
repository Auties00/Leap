package it.auties.leap.socket.async;

import it.auties.leap.socket.SocketApplicationLayerFactory;
import it.auties.leap.socket.async.applicationLayer.AsyncPlainSocketApplicationLayer;
import it.auties.leap.socket.async.applicationLayer.AsyncSecureSocketApplicationLayer;
import it.auties.leap.tls.TlsConfig;

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
