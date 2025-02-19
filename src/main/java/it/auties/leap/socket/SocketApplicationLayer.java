package it.auties.leap.socket;

import it.auties.leap.socket.async.applicationLayer.AsyncSocketApplicationLayer;
import it.auties.leap.socket.blocking.applicationLayer.BlockingSocketApplicationLayer;

public sealed interface SocketApplicationLayer permits AsyncSocketApplicationLayer, BlockingSocketApplicationLayer {
    SocketTransportLayer transportLayer();
}
