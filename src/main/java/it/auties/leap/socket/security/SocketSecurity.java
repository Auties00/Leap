package it.auties.leap.socket.security;

import it.auties.leap.http.decoder.HttpDecodable;
import it.auties.leap.socket.SocketOption;
import it.auties.leap.socket.platform.SocketPlatform;

import java.nio.ByteBuffer;
import java.util.concurrent.CompletableFuture;

public abstract class SocketSecurity implements HttpDecodable {
    protected final SocketPlatform<?> transmissionLayer;

    protected SocketSecurity(SocketPlatform<?> transmissionLayer) {
        this.transmissionLayer = transmissionLayer;
    }

    public abstract CompletableFuture<Void> handshake();

    public abstract boolean isSecure();

    public abstract CompletableFuture<Void> write(ByteBuffer buffer);

    public abstract CompletableFuture<ByteBuffer> read(ByteBuffer buffer, boolean lastRead);

    public CompletableFuture<ByteBuffer> readPlain(ByteBuffer buffer, boolean lastRead) {
        return transmissionLayer.read(buffer).thenApply(_ -> {
            if (lastRead) {
                buffer.flip();
            }

            return buffer;
        });
    }

    public CompletableFuture<ByteBuffer> readPlainFully(ByteBuffer buffer) {
        return readPlain(buffer, false).thenCompose(_ -> {
            if (buffer.hasRemaining()) {
                return readFully(buffer);
            }

            buffer.flip();
            return CompletableFuture.completedFuture(buffer);
        });
    }

    protected CompletableFuture<Void> writePlain(ByteBuffer buffer) {
        return transmissionLayer.write(buffer);
    }

    @Override
    public CompletableFuture<ByteBuffer> read() {
        var buffer = ByteBuffer.allocate(transmissionLayer.getOption(SocketOption.readBufferSize()));
        return read(buffer, true);
    }

    @Override
    public CompletableFuture<ByteBuffer> readFully(int length) {
        if (length < 0) {
            return CompletableFuture.failedFuture(new IllegalArgumentException("Cannot read %s bytes from socket: negative length".formatted(length)));
        }

        var buffer = ByteBuffer.allocate(length);
        return readFully(buffer);
    }

    public CompletableFuture<ByteBuffer> readFully(ByteBuffer buffer) {
        return read(buffer, false).thenCompose(_ -> {
            if (buffer.hasRemaining()) {
                return readFully(buffer);
            }

            buffer.flip();
            return CompletableFuture.completedFuture(buffer);
        });
    }
}
