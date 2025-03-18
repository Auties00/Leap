package it.auties.leap.http.exchange.body;

import it.auties.leap.http.HttpVersion;
import it.auties.leap.http.exchange.body.implementation.BufferBody;
import it.auties.leap.http.exchange.body.implementation.EmptyBody;
import it.auties.leap.http.exchange.body.implementation.StreamBody;
import it.auties.leap.http.exchange.body.implementation.StringBody;
import it.auties.leap.http.exchange.headers.HttpHeaders;

import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

public interface HttpBodyDeserializer<T> {
    HttpBody<T> deserialize(HttpVersion version, HttpHeaders headers, ByteBuffer buffer);

    @SuppressWarnings("unchecked")
    static <T> HttpBodyDeserializer<T> empty() {
        return EmptyBody.deserializer();
    }

    static HttpBodyDeserializer<String> fromString() {
        return StringBody.deserializer(StandardCharsets.UTF_8);
    }

    static HttpBodyDeserializer<String> fromString(Charset charset) {
        return StringBody.deserializer(charset);
    }

    static HttpBodyDeserializer<ByteBuffer> fromBytes() {
        return BufferBody.deserializer();
    }

    static HttpBodyDeserializer<ByteBuffer> fromBuffer() {
        return BufferBody.deserializer();
    }

    static HttpBodyDeserializer<InputStream> fromStream() {
        return StreamBody.deserializer();
    }
}
