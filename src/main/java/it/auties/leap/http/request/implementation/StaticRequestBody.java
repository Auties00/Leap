package it.auties.leap.http.request.implementation;

import it.auties.leap.http.request.HttpRequestBody;

import java.nio.ByteBuffer;
import java.util.OptionalInt;

public final class StaticRequestBody implements HttpRequestBody {
    private final ByteBuffer buffer;

    public StaticRequestBody(ByteBuffer buffer) {
        this.buffer = buffer;
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
