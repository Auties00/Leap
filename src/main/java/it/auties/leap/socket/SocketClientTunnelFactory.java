package it.auties.leap.socket;

import it.auties.leap.socket.async.AsyncSocketTunnelLayerFactory;
import it.auties.leap.socket.blocking.BlockingSocketTunnelLayerFactory;

import java.net.URI;

public sealed interface SocketClientTunnelFactory<T extends SocketApplicationLayer> permits BlockingSocketTunnelLayerFactory, AsyncSocketTunnelLayerFactory {
    SocketTunnelLayer newTunnel(T applicationLayer, URI proxy);
}
