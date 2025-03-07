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
    private static final HttpBodyDeserializer<InputStream> DESERIALIZER = buffer -> {
        var stream = new InputStream() {
            @Override
            public int read() {
                return buffer.get() & 0xFF;
            }
        };
        return new StreamBody(stream, 1024);
    };

    private final InputStream inputStream;
    private final int chunkSize;
    public StreamBody(InputStream inputStream, int chunkSize) {
        this.inputStream = inputStream;
        this.chunkSize = chunkSize;
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
    public HttpBodyDeserializer<InputStream> deserializer() {
        return DESERIALIZER;
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        try {
            var chunk = new byte[chunkSize];
            int read;
            while ((read = inputStream.read(chunk)) != -1) {
                buffer.put(chunk, 0, read);
            }
        }catch (IOException exception) {
            throw new UncheckedIOException(exception);
        }
    }
}
