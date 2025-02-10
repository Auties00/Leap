package it.auties.leap.socket;

import it.auties.leap.socket.async.AsyncSocketTransportLayerFactory;
import it.auties.leap.socket.async.AsyncSocketTunnelLayerFactory;
import it.auties.leap.socket.blocking.BlockingSocketTransportLayerFactory;
import it.auties.leap.socket.blocking.BlockingSocketTunnelLayerFactory;

public sealed interface SocketTransportLayerFactory permits AsyncSocketTransportLayerFactory, AsyncSocketTunnelLayerFactory, BlockingSocketTransportLayerFactory, BlockingSocketTunnelLayerFactory {
    SocketTransportLayer newTransport(SocketProtocol protocol);
}
