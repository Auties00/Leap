package it.auties.leap.socket.security;

import it.auties.leap.socket.transmission.SocketTransmissionLayer;

import java.nio.ByteBuffer;
import java.util.concurrent.CompletableFuture;

final class PlainSecurityLayer extends SocketSecurityLayer {
    PlainSecurityLayer(SocketTransmissionLayer<?> channel) {
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
