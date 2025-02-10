package it.auties.leap.socket;

import it.auties.leap.socket.async.AsyncSocketApplicationLayer;
import it.auties.leap.socket.blocking.BlockingSocketApplicationLayer;

public sealed interface SocketApplicationLayer permits AsyncSocketApplicationLayer, BlockingSocketApplicationLayer {
    SocketTransportLayer transportLayer();
}
