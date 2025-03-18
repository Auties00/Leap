package it.auties.leap.http.exchange.body.implementation;

import it.auties.leap.http.exchange.body.HttpBody;
import it.auties.leap.http.exchange.body.HttpBodyDeserializer;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.util.Optional;
import java.util.OptionalInt;

public final class StreamBody implements HttpBody<InputStream> {
    private static final HttpBodyDeserializer<InputStream> DESERIALIZER = ((_, _, buffer) -> new StreamBody(new ByteBufferBackedInputStream(buffer)));

    public static HttpBodyDeserializer<InputStream> deserializer() {
        return DESERIALIZER;
    }

    private final InputStream inputStream;

    public StreamBody(InputStream inputStream) {
        this.inputStream = inputStream;
    }

    @Override
    public Optional<InputStream> content() {
        return Optional.of(inputStream);
    }

    @Override
    public OptionalInt length() {
        return OptionalInt.empty();
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        try {
            int current;
            while ((current = inputStream.read()) != -1) {
                buffer.put((byte) current);
            }
        }catch (IOException exception) {
            throw new UncheckedIOException(exception);
        }
    }

    private static final class ByteBufferBackedInputStream extends InputStream {
        private final ByteBuffer buf;
        private ByteBufferBackedInputStream(ByteBuffer buf) {
            this.buf = buf;
        }

        @Override
        public synchronized int read() {
            if (!buf.hasRemaining()) {
                return -1;
            }
            return buf.get() & 0xFF;
        }

        @Override
        public synchronized int read(byte[] bytes, int off, int len) {
            len = Math.min(len, buf.remaining());
            buf.get(bytes, off, len);
            return len;
        }
    }
}
