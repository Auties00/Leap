package it.auties.leap.socket.layer;

import it.auties.leap.http.decoder.HttpDecodable;

import javax.net.ssl.*;
import java.io.EOFException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.InvalidMarkException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicBoolean;

public sealed abstract class SocketSecurityLayer implements HttpDecodable {
    final SocketTransmissionLayer<?> transmissionLayer;

    private SocketSecurityLayer(SocketTransmissionLayer<?> transmissionLayer) {
        this.transmissionLayer = transmissionLayer;
    }

    public static SocketSecurityLayer ofPlain(SocketTransmissionLayer<?> transmissionLayer) {
        return new Plain(transmissionLayer);
    }

    public static SocketSecurityLayer ofSecure(SocketTransmissionLayer<?> transmissionLayer, SSLContext sslContext, SSLParameters sslParameters) {
        return new Secure(transmissionLayer, sslContext, sslParameters);
    }

    public abstract CompletableFuture<Void> handshake(String hostname, int port);

    public abstract boolean isSecure();

    public abstract CompletableFuture<Void> write(ByteBuffer buffer);

    public abstract CompletableFuture<ByteBuffer> read(ByteBuffer buffer, boolean lastRead);

    CompletableFuture<ByteBuffer> readPlain(ByteBuffer buffer, boolean lastRead) {
        return transmissionLayer.read(buffer).thenApply(_ -> {
            if (lastRead) {
                buffer.flip();
            }

            return buffer;
        });
    }

    CompletableFuture<Void> writePlain(ByteBuffer buffer) {
        return transmissionLayer.write(buffer);
    }

    @Override
    public CompletableFuture<ByteBuffer> read() {
        var buffer = ByteBuffer.allocate(transmissionLayer.readBufferSize);
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

    private static final class Plain extends SocketSecurityLayer {
        private Plain(SocketTransmissionLayer<?> channel) {
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
        public CompletableFuture<Void> handshake(String hostname, int port) {
            return CompletableFuture.completedFuture(null);
        }
    }

    private static final class Secure extends SocketSecurityLayer {
        private final AtomicBoolean sslHandshakeCompleted;
        private final SSLContext sslContext;
        private final SSLParameters sslParameters;
        private SSLEngine sslEngine;
        private ByteBuffer sslReadBuffer, sslWriteBuffer, sslOutputBuffer;
        private CompletableFuture<Void> sslHandshake;
        private Secure(SocketTransmissionLayer<?> channel, SSLContext sslContext, SSLParameters sslParameters) {
            super(channel);
            this.sslHandshakeCompleted = new AtomicBoolean();
            this.sslContext = sslContext;
            this.sslParameters = sslParameters;
        }

        @Override
        public boolean isSecure() {
            return true;
        }

        @Override
        public CompletableFuture<Void> handshake(String hostname, int port) {
            try {
                if (sslHandshakeCompleted.get()) {
                    return CompletableFuture.completedFuture(null);
                }

                if (sslHandshake != null) {
                    return sslHandshake;
                }

                synchronized (sslHandshakeCompleted) {
                    if (sslHandshake != null) {
                        return sslHandshake;
                    }

                    this.sslEngine = sslContext.createSSLEngine(hostname, port == -1 ? 443 : port);
                    sslEngine.setUseClientMode(true);
                    sslEngine.setSSLParameters(sslParameters);
                    var bufferSize = sslEngine.getSession().getPacketBufferSize();
                    this.sslReadBuffer = ByteBuffer.allocate(bufferSize);
                    this.sslWriteBuffer = ByteBuffer.allocate(bufferSize);
                    this.sslOutputBuffer = ByteBuffer.allocate(bufferSize);
                    sslEngine.beginHandshake();
                    sslReadBuffer.position(sslReadBuffer.limit());
                    return this.sslHandshake = handleSslHandshakeStatus(null);
                }
            } catch (Throwable throwable) {
                return CompletableFuture.failedFuture(throwable);
            }
        }

        private CompletableFuture<Void> handleSslHandshakeStatus(SSLEngineResult.Status status) {
            return switch (sslEngine.getHandshakeStatus()) {
                case NEED_WRAP -> doSslHandshakeWrap();
                case NEED_UNWRAP, NEED_UNWRAP_AGAIN ->
                        doSslHandshakeUnwrap(status == SSLEngineResult.Status.BUFFER_UNDERFLOW);
                case NEED_TASK -> doSslHandshakeTasks();
                case FINISHED -> finishSslHandshake();
                case NOT_HANDSHAKING -> CompletableFuture.failedFuture(new IOException("Cannot complete handshake"));
            };
        }

        private CompletableFuture<Void> finishSslHandshake() {
            sslHandshakeCompleted.set(true);
            sslOutputBuffer.clear();
            return CompletableFuture.completedFuture(null);
        }

        private CompletableFuture<Void> doSslHandshakeTasks() {
            Runnable runnable;
            while ((runnable = sslEngine.getDelegatedTask()) != null) {
                runnable.run();
            }

            return handleSslHandshakeStatus(null);
        }

        private CompletableFuture<Void> doSslHandshakeUnwrap(boolean forceRead) {
            sslReadBuffer.compact();
            if (!forceRead && sslReadBuffer.position() != 0) {
                sslReadBuffer.flip();
                return doSSlHandshakeUnwrapOperation();
            }

            return readPlain(sslReadBuffer, true)
                    .thenCompose(_ -> doSSlHandshakeUnwrapOperation());
        }

        private CompletableFuture<Void> doSSlHandshakeUnwrapOperation() {
            try {
                var result = sslEngine.unwrap(sslReadBuffer, sslOutputBuffer);
                if (isHandshakeFinished(result, false)) {
                    return finishSslHandshake();
                } else {
                    return handleSslHandshakeStatus(result.getStatus());
                }
            } catch (Throwable throwable) {
                return CompletableFuture.failedFuture(throwable);
            }
        }

        private CompletableFuture<Void> doSslHandshakeWrap() {
            try {
                sslWriteBuffer.clear();
                var result = sslEngine.wrap(sslOutputBuffer, sslWriteBuffer);
                var isHandshakeFinished = isHandshakeFinished(result, true);
                sslWriteBuffer.flip();
                return writePlain(sslWriteBuffer).thenCompose(_ -> {
                    if (isHandshakeFinished) {
                        return finishSslHandshake();
                    } else {
                        return handleSslHandshakeStatus(null);
                    }
                });
            } catch (Throwable throwable) {
                return CompletableFuture.failedFuture(throwable);
            }
        }

        private boolean isHandshakeFinished(SSLEngineResult result, boolean wrap) {
            var sslEngineStatus = result.getStatus();
            if (sslEngineStatus != SSLEngineResult.Status.OK && (wrap || sslEngineStatus != SSLEngineResult.Status.BUFFER_UNDERFLOW)) {
                throw new IllegalStateException("SSL handshake operation failed with status: " + sslEngineStatus);
            }

            if (wrap && result.bytesConsumed() != 0) {
                throw new IllegalStateException("SSL handshake operation failed with status: no bytes consumed");
            }

            if (!wrap && result.bytesProduced() != 0) {
                throw new IllegalStateException("SSL handshake operation failed with status: no bytes produced");
            }

            var sslHandshakeStatus = result.getHandshakeStatus();
            return sslHandshakeStatus == SSLEngineResult.HandshakeStatus.FINISHED;
        }

        @Override
        public CompletableFuture<ByteBuffer> read(ByteBuffer buffer, boolean lastRead) {
            if (!sslHandshakeCompleted.get()) {
                return readPlain(buffer, lastRead);
            }

            return readSecure(buffer, lastRead);
        }

        private CompletableFuture<ByteBuffer> readSecure(ByteBuffer buffer, boolean lastRead) {
            try {
                var bytesCopied = readFromBufferedOutput(buffer, lastRead);
                if (bytesCopied != 0) {
                    return CompletableFuture.completedFuture(buffer);
                } else if (sslReadBuffer.hasRemaining()) {
                    return decodeSslBuffer(buffer, lastRead);
                } else {
                    return fillSslBuffer(buffer, lastRead);
                }
            }catch (Throwable throwable) {
                return CompletableFuture.failedFuture(throwable);
            }
        }

        private CompletableFuture<ByteBuffer> fillSslBuffer(ByteBuffer buffer, boolean lastRead) {
            sslReadBuffer.compact();
            return readPlain(sslReadBuffer, true)
                    .thenCompose(_ -> decodeSslBuffer(buffer, lastRead));
        }

        private CompletableFuture<ByteBuffer> decodeSslBuffer(ByteBuffer buffer, boolean lastRead) {
            try {
                var unwrapResult = sslEngine.unwrap(sslReadBuffer, sslOutputBuffer);
                return switch (unwrapResult.getStatus()) {
                    case OK -> {
                        if (unwrapResult.bytesProduced() == 0) {
                            sslOutputBuffer.mark();
                            yield read(buffer, lastRead);
                        } else {
                            readFromBufferedOutput(buffer, lastRead);
                            yield CompletableFuture.completedFuture(buffer);
                        }
                    }
                    case BUFFER_UNDERFLOW ->
                            fillSslBuffer(buffer, lastRead);
                    case BUFFER_OVERFLOW ->
                            CompletableFuture.failedFuture(new IllegalStateException("SSL output buffer overflow"));
                    case CLOSED ->
                            CompletableFuture.failedFuture(new EOFException());
                };
            } catch (Throwable throwable) {
                return CompletableFuture.failedFuture(throwable);
            }
        }

        private int readFromBufferedOutput(ByteBuffer buffer, boolean lastRead) {
            var writePosition = sslOutputBuffer.position();
            if (writePosition == 0) {
                return 0;
            }

            var bytesRead = 0;
            var writeLimit = sslOutputBuffer.limit();
            sslOutputBuffer.limit(writePosition);
            try {
                sslOutputBuffer.reset(); // Go back to last read position
            } catch (InvalidMarkException exception) {
                sslOutputBuffer.flip(); // This can happen if unwrapResult.bytesProduced() != 0 on the first call
            }
            while (buffer.hasRemaining() && sslOutputBuffer.hasRemaining()) {
                buffer.put(sslOutputBuffer.get());
                bytesRead++;
            }

            if (!sslOutputBuffer.hasRemaining()) {
                sslOutputBuffer.clear();
                sslOutputBuffer.mark();
            } else {
                sslOutputBuffer.limit(writeLimit);
                sslOutputBuffer.mark();
                sslOutputBuffer.position(writePosition);
            }

            if (lastRead) {
                buffer.flip();
            }

            return bytesRead;
        }

        @Override
        public CompletableFuture<Void> write(ByteBuffer buffer) {
            if (!sslHandshakeCompleted.get()) {
                return writePlain(buffer);
            }

            return writeSecure(buffer);
        }

        private CompletableFuture<Void> writeSecure(ByteBuffer buffer) {
            try {
                if (!buffer.hasRemaining()) {
                    return CompletableFuture.completedFuture(null);
                }

                sslWriteBuffer.clear();
                var wrapResult = sslEngine.wrap(buffer, sslWriteBuffer);
                var status = wrapResult.getStatus();
                if (status != SSLEngineResult.Status.OK && status != SSLEngineResult.Status.BUFFER_OVERFLOW) {
                    return CompletableFuture.failedFuture(new IllegalStateException("SSL wrap failed with status: " + status));
                }

                sslWriteBuffer.flip();
                return writePlain(sslWriteBuffer)
                        .thenCompose(_ -> writeSecure(buffer));
            } catch (Throwable throwable) {
                return CompletableFuture.failedFuture(throwable);
            }
        }
    }
}
