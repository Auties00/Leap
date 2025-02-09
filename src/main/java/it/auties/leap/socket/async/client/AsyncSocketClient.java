package it.auties.leap.socket.async.client;

import it.auties.leap.socket.SocketClient;
import it.auties.leap.socket.SocketProtocol;
import it.auties.leap.socket.async.AsyncSocketImplementation;

import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.util.concurrent.CompletableFuture;

public non-sealed interface AsyncSocketClient extends SocketClient {
    CompletableFuture<Void> connect(InetSocketAddress address);

    CompletableFuture<Void>  write(ByteBuffer buffer);

    CompletableFuture<Void>  read(ByteBuffer buffer);

    CompletableFuture<Void>  readFully(ByteBuffer buffer);

    @Override
    AsyncSocketImplementation implementation();

    default CompletableFuture<Void>  write(byte[] data) {
        return write(data, 0, data.length);
    }

    default CompletableFuture<Void>  write(byte[] data, int offset, int length) {
        return write(ByteBuffer.wrap(data, offset, length));
    }

    static AsyncSocketClientBuilder newBuilder(SocketProtocol protocol) {
        return new AsyncSocketClientBuilder(protocol);
    }
}
