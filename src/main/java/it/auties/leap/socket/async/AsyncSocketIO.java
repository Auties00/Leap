package it.auties.leap.socket.async;

import it.auties.leap.socket.SocketIOProvider;

import java.nio.ByteBuffer;
import java.util.concurrent.CompletableFuture;

public sealed interface AsyncSocketIO extends SocketIOProvider permits AsyncSocketApplicationLayer, AsyncSocketClient, AsyncSocketTransportLayer {
    default CompletableFuture<Void> write(byte[] data) {
        return write(data, 0, data.length);
    }

    default CompletableFuture<Void> write(byte[] data, int offset, int length) {
        return write(ByteBuffer.wrap(data, offset, length));
    }

    CompletableFuture<Void> write(ByteBuffer buffer);

    CompletableFuture<Void> read(ByteBuffer buffer);

    CompletableFuture<Void> readFully(ByteBuffer buffer);
}
