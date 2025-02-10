package it.auties.leap.socket.blocking;

import it.auties.leap.socket.SocketProtocol;
import it.auties.leap.socket.SocketTransportLayer;

import java.net.InetSocketAddress;

public non-sealed abstract class BlockingSocketTransportLayer extends SocketTransportLayer implements BlockingSocketIO {
    public BlockingSocketTransportLayer(SocketProtocol protocol) {
        super(protocol);
    }

    public abstract void connect(InetSocketAddress address);
}
