package it.auties.leap.socket.blocking.transportLayer;

import it.auties.leap.socket.SocketProtocol;
import it.auties.leap.socket.SocketTransportLayer;
import it.auties.leap.socket.blocking.BlockingSocketIO;

import java.net.InetSocketAddress;

public non-sealed abstract class BlockingSocketTransportLayer extends SocketTransportLayer implements BlockingSocketIO {
    public BlockingSocketTransportLayer(SocketProtocol protocol) {
        super(protocol);
    }

    public abstract void connect(InetSocketAddress address);
}
