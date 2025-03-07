package it.auties.leap.http.exchange.body;

import it.auties.leap.http.exchange.body.implementation.EmptyBody;
import it.auties.leap.http.exchange.body.implementation.StringBody;
import it.auties.leap.http.exchange.body.implementation.StreamBody;

import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.stream.Collectors;

public interface HttpBody<T> {
    Optional<T> content();
    OptionalInt length();
    void serialize(ByteBuffer buffer);
    HttpBodyDeserializer<T> deserializer();

    @SuppressWarnings("unchecked")
    static <T> HttpBody<T> empty() {
        return EmptyBody.instance();
    }

    static HttpBody<String> fromString(String text) {
        return new StringBody(text, StandardCharsets.UTF_8);
    }

    static HttpBody<String> fromString(String text, Charset charset) {
        return new StringBody(text, charset);
    }

    static HttpBody<ByteBuffer> fromBytes(byte[] binary) {
        return new StringBody(ByteBuffer.wrap(binary, 0, binary.length));
    }

    static HttpBody<ByteBuffer> fromBytes(byte[] binary, int offset, int length) {
        return new StringBody(ByteBuffer.wrap(binary, offset, length));
    }

    static HttpBody<ByteBuffer> fromBuffer(ByteBuffer buffer) {
        return new StringBody(buffer);
    }

    static HttpBody<InputStream> fromStream(InputStream inputStream, int chunkSize) {
        return new StreamBody(inputStream, chunkSize);
    }

    static HttpBody<String> fromFormData(Map<String, ?> text) {
        var body = text.entrySet()
                .stream()
                .map(entry -> entry.getKey() + "=" + entry.getValue())
                .collect(Collectors.joining("&"));
        return new StringBody(body, StandardCharsets.UTF_8);
    }
}
