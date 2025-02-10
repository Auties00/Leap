package it.auties.leap.socket;

import it.auties.leap.socket.async.AsyncSocketTunnelLayer;
import it.auties.leap.socket.blocking.BlockingSocketTunnelLayer;

public sealed interface SocketTunnelLayer permits AsyncSocketTunnelLayer, BlockingSocketTunnelLayer {

}
