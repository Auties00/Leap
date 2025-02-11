package it.auties.leap.socket;

import it.auties.leap.socket.async.AsyncSocketApplicationLayerFactory;
import it.auties.leap.socket.blocking.BlockingSocketApplicationLayerFactory;

public sealed interface SocketApplicationLayerFactory<T extends SocketTransportLayer, P> permits AsyncSocketApplicationLayerFactory, BlockingSocketApplicationLayerFactory {
    SocketApplicationLayer newApplication(T applicationLayer, P param);
}
