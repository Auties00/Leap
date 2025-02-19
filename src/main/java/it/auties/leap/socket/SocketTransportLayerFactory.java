package it.auties.leap.socket;

import it.auties.leap.socket.async.transportLayer.AsyncSocketTransportLayerFactory;
import it.auties.leap.socket.blocking.transportLayer.BlockingSocketTransportLayerFactory;

public sealed interface SocketTransportLayerFactory permits AsyncSocketTransportLayerFactory, BlockingSocketTransportLayerFactory {
    SocketTransportLayer newTransport(SocketProtocol protocol);
}
