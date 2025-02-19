package it.auties.leap.socket.async.transportLayer;

import it.auties.leap.socket.SocketProtocol;
import it.auties.leap.socket.SocketTransportLayer;
import it.auties.leap.socket.async.AsyncSocketIO;

import java.net.InetSocketAddress;
import java.util.concurrent.CompletableFuture;

public non-sealed abstract class AsyncSocketTransportLayer extends SocketTransportLayer implements AsyncSocketIO {
    public AsyncSocketTransportLayer(SocketProtocol protocol) {
        super(protocol);
    }

    public abstract CompletableFuture<Void> connect(InetSocketAddress address);
}
