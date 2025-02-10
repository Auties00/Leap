package it.auties.leap.socket;

import it.auties.leap.socket.async.AsyncSocketTransportLayer;
import it.auties.leap.socket.blocking.BlockingSocketTransportLayer;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.Optional;

public sealed abstract class SocketTransportLayer implements SocketMetadataProvider permits AsyncSocketTransportLayer, BlockingSocketTransportLayer {
    protected final SocketProtocol protocol;

    public SocketTransportLayer(SocketProtocol protocol) {
        this.protocol = protocol;
    }

    public abstract boolean isConnected();
    
    public abstract Optional<InetSocketAddress> address();
    public abstract void setAddress(InetSocketAddress address);

    public abstract <V> V getOption(SocketOption<V> option);
    public abstract <V> void setOption(SocketOption<V> option, V value);

    public abstract void close() throws IOException;
}
