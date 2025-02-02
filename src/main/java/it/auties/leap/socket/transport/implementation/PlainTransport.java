package it.auties.leap.socket.transport.implementation;

import it.auties.leap.socket.implementation.SocketImplementation;
import it.auties.leap.socket.transport.SocketTransport;

import java.nio.ByteBuffer;
import java.util.concurrent.CompletableFuture;

public final class PlainTransport extends SocketTransport {
    public PlainTransport(SocketImplementation channel) {
        super(channel);
    }

    @Override
    public boolean isSecure() {
        return false;
    }

    @Override
    public CompletableFuture<Void> write(ByteBuffer buffer) {
        return writePlain(buffer);
    }

    @Override
    public CompletableFuture<ByteBuffer> read(ByteBuffer buffer, boolean lastRead) {
        return readPlain(buffer, lastRead);
    }

    @Override
    public CompletableFuture<Void> handshake() {
        return CompletableFuture.completedFuture(null);
    }
}
