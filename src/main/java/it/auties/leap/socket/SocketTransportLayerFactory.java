package it.auties.leap.socket;

import it.auties.leap.socket.async.AsyncSocketTransportLayerFactory;
import it.auties.leap.socket.blocking.BlockingSocketTransportLayerFactory;

public sealed interface SocketTransportLayerFactory permits AsyncSocketTransportLayerFactory, BlockingSocketTransportLayerFactory {
    SocketTransportLayer newTransport(SocketProtocol protocol);
}
