package it.auties.leap.socket;

import it.auties.leap.socket.async.applicationLayer.AsyncSocketApplicationLayer;
import it.auties.leap.socket.blocking.applicationLayer.BlockingSocketApplicationLayer;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.Optional;

public sealed interface SocketApplicationLayer permits AsyncSocketApplicationLayer, BlockingSocketApplicationLayer {
    boolean isConnected();

    Optional<InetSocketAddress> address();
    void setAddress(InetSocketAddress address);

    <V> V getOption(SocketOption<V> option);
    <V> void setOption(SocketOption<V> option, V value);

    void close(boolean error) throws IOException;
}
