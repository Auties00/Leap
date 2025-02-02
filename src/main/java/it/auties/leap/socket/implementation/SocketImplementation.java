package it.auties.leap.socket.implementation;

import it.auties.leap.socket.SocketOption;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

public interface SocketImplementation extends AutoCloseable {
    CompletableFuture<Void> connect(InetSocketAddress address);

    CompletableFuture<Void> write(ByteBuffer input);

    CompletableFuture<ByteBuffer> read(ByteBuffer output);

    <V> void setOption(SocketOption<V> option, V value);

    <V> V getOption(SocketOption<V> option);

    boolean isConnected();

    Optional<InetSocketAddress> remoteAddress();

    void setRemoteAddress(InetSocketAddress address);

    @Override
    void close() throws IOException;
}
