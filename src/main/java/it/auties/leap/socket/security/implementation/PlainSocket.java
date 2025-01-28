package it.auties.leap.socket.security.implementation;

import it.auties.leap.socket.platform.SocketPlatform;
import it.auties.leap.socket.security.SocketSecurity;

import java.nio.ByteBuffer;
import java.util.concurrent.CompletableFuture;

public final class PlainSocket extends SocketSecurity {
    public PlainSocket(SocketPlatform<?> channel) {
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
