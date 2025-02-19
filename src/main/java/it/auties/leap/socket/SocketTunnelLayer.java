package it.auties.leap.socket;

import it.auties.leap.socket.async.tunnelLayer.AsyncSocketTunnelLayer;
import it.auties.leap.socket.blocking.tunnelLayer.BlockingSocketTunnelLayer;

public sealed interface SocketTunnelLayer permits AsyncSocketTunnelLayer, BlockingSocketTunnelLayer {

}
