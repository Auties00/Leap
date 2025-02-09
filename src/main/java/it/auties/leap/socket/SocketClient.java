package it.auties.leap.socket;

import it.auties.leap.socket.async.client.AsyncSocketClient;
import it.auties.leap.socket.blocking.client.BlockingSocketClient;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.Optional;

public sealed interface SocketClient extends AutoCloseable permits AsyncSocketClient, BlockingSocketClient {
    boolean isConnected();

    @Override
    void close() throws IOException;
    
    Optional<InetSocketAddress> address();
    void setAddress(InetSocketAddress address);

    <V> V getOption(SocketOption<V> option);
    <V> void setOption(SocketOption<V> option, V value);

    SocketImplementation implementation();

    static SocketClientBuilder newBuilder() {
        return SocketClientBuilder.instance();
    }
}
