package it.auties.leap.socket.async;

import it.auties.leap.socket.SocketIO;
import it.auties.leap.socket.SocketIOProvider;
import it.auties.leap.socket.async.applicationLayer.AsyncSocketApplicationLayer;
import it.auties.leap.socket.async.transportLayer.AsyncSocketTransportLayer;

import java.nio.ByteBuffer;
import java.util.concurrent.CompletableFuture;

public sealed interface AsyncSocketIO extends SocketIOProvider, SocketIO permits AsyncSocketApplicationLayer, AsyncSocketClient, AsyncSocketTransportLayer {
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
