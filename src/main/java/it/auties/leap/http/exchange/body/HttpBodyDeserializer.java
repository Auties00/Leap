package it.auties.leap.http.exchange.body;

import it.auties.leap.http.HttpVersion;
import it.auties.leap.http.exchange.body.implementation.*;
import it.auties.leap.http.exchange.headers.HttpHeaders;

import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Map;

public interface HttpBodyDeserializer<T> {
    HttpBody<T> deserialize(HttpVersion version, HttpHeaders headers, ByteBuffer buffer);

    @SuppressWarnings("unchecked")
    static <T> HttpBodyDeserializer<T> discard() {
        return EmptyBody.deserializer();
    }

    static HttpBodyDeserializer<String> ofString() {
        return StringBody.deserializer(StandardCharsets.UTF_8);
    }

    static HttpBodyDeserializer<String> ofString(Charset charset) {
        return StringBody.deserializer(charset);
    }

    static HttpBodyDeserializer<ByteBuffer> ofBytes() {
        return BufferBody.deserializer();
    }

    static HttpBodyDeserializer<ByteBuffer> ofBuffer() {
        return BufferBody.deserializer();
    }

    static HttpBodyDeserializer<InputStream> ofStream() {
        return StreamBody.deserializer();
    }

    static HttpBodyDeserializer<Map<String, String>> ofFormData() {
        return FormBody.deserializer(StandardCharsets.UTF_8);
    }
}
