package it.auties.leap.http.exchange.body;

import it.auties.leap.http.HttpVersion;

import java.nio.ByteBuffer;
import java.util.Map;

public interface HttpBodyDeserializer<T> {
    HttpBody<T> deserialize(HttpVersion version, Map<String, String> headers, ByteBuffer buffer);
}
