package it.auties.leap.http.exchange.body.implementation;

import it.auties.leap.http.exchange.body.HttpBody;
import it.auties.leap.http.exchange.body.HttpBodyDeserializer;

import java.nio.ByteBuffer;
import java.util.Optional;
import java.util.OptionalInt;

public final class BufferBody implements HttpBody<ByteBuffer> {
    private static final HttpBodyDeserializer<ByteBuffer> DESERIALIZER = ((_, _, buffer) -> new BufferBody(buffer));

    public static HttpBodyDeserializer<ByteBuffer> deserializer() {
        return DESERIALIZER;
    }

    private final ByteBuffer buffer;

    public BufferBody(ByteBuffer buffer) {
        this.buffer = buffer.asReadOnlyBuffer();
    }

    @Override
    public Optional<ByteBuffer> content() {
        return Optional.of(buffer);
    }

    @Override
    public OptionalInt length() {
        return OptionalInt.of(buffer.remaining());
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        buffer.put(this.buffer);
    }
}
