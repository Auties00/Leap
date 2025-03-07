package it.auties.leap.http.exchange.body.implementation;

import it.auties.leap.http.exchange.body.HttpBody;
import it.auties.leap.http.exchange.body.HttpBodyDeserializer;

import java.nio.ByteBuffer;
import java.util.Optional;
import java.util.OptionalInt;

@SuppressWarnings({"rawtypes"})
public final class EmptyBody implements HttpBody {
    private static final EmptyBody INSTANCE = new EmptyBody();
    private static final HttpBodyDeserializer DESERIALIZER = (_) -> INSTANCE;

    private EmptyBody() {

    }

    public static HttpBody instance() {
        return INSTANCE;
    }

    @Override
    public Optional content() {
        return Optional.empty();
    }

    @Override
    public OptionalInt length() {
        return OptionalInt.empty();
    }

    @Override
    public void serialize(ByteBuffer buffer) {

    }

    @Override
    public HttpBodyDeserializer deserializer() {
        return DESERIALIZER;
    }
}
