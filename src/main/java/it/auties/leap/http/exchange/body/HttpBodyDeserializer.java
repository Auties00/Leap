package it.auties.leap.http.exchange.body;

import java.nio.ByteBuffer;

public interface HttpBodyDeserializer<T> {
    HttpBody<T> deserialize(ByteBuffer buffer);
}
