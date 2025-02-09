package it.auties.leap.socket;

import it.auties.leap.socket.async.AsyncSocketImplementation;
import it.auties.leap.socket.blocking.BlockingSocketImplementation;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.Optional;

public sealed interface SocketImplementation extends AutoCloseable permits AsyncSocketImplementation, BlockingSocketImplementation {
    boolean isConnected();
    
    Optional<InetSocketAddress> address();
    void setAddress(InetSocketAddress address);

    <V> V getOption(SocketOption<V> option);
    <V> void setOption(SocketOption<V> option, V value);

    @Override
    void close() throws IOException;
}
