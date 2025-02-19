package it.auties.leap.socket;

import it.auties.leap.socket.async.tunnelLayer.AsyncSocketTunnelLayerFactory;
import it.auties.leap.socket.blocking.tunnelLayer.BlockingSocketTunnelLayerFactory;

import java.net.URI;

public sealed interface SocketTunnelLayerFactory<T extends SocketApplicationLayer> permits BlockingSocketTunnelLayerFactory, AsyncSocketTunnelLayerFactory {
    SocketTunnelLayer newTunnel(T applicationLayer, URI location);
}
