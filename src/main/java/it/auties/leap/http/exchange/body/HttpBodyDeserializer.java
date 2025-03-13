package it.auties.leap.http.exchange.body;

import it.auties.leap.http.HttpVersion;
import it.auties.leap.http.exchange.headers.HttpHeaders;

import java.nio.ByteBuffer;

public interface HttpBodyDeserializer<T> {
    HttpBody<T> deserialize(HttpVersion version, HttpHeaders headers, ByteBuffer buffer);
}
