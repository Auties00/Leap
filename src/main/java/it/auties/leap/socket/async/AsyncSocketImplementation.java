package it.auties.leap.socket.async;

import it.auties.leap.socket.SocketImplementation;

import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.util.concurrent.CompletableFuture;

public non-sealed interface AsyncSocketImplementation extends SocketImplementation{
    CompletableFuture<Void> connect(InetSocketAddress address);

    CompletableFuture<Void> write(ByteBuffer buffer);

    CompletableFuture<Void> read(ByteBuffer buffer);

    CompletableFuture<Void> readFully(ByteBuffer buffer);

    default CompletableFuture<Void> write(byte[] data) {
        return write(data, 0, data.length);
    }

    default CompletableFuture<Void> write(byte[] data, int offset, int length) {
        return write(ByteBuffer.wrap(data, offset, length));
    }
}
