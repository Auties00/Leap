package it.auties.leap.socket;

import java.net.InetSocketAddress;
import java.util.Optional;

public sealed interface SocketMetadataProvider permits SocketClient, SocketTransportLayer {
    boolean isConnected();

    Optional<InetSocketAddress> address();
    void setAddress(InetSocketAddress address);

    <V> V getOption(SocketOption<V> option);
    <V> void setOption(SocketOption<V> option, V value);
}
