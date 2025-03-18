package it.auties.leap.http.exchange.body;

import it.auties.leap.http.exchange.body.implementation.*;

import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.OptionalInt;

public interface HttpBody<T> {
    T content();
    OptionalInt length();
    void serialize(ByteBuffer buffer);

    @SuppressWarnings("unchecked")
    static <T> HttpBody<T> empty() {
        return EmptyBody.instance();
    }

    static HttpBody<String> ofString(String text) {
        return new StringBody(text, StandardCharsets.UTF_8);
    }

    static HttpBody<String> ofString(String text, Charset charset) {
        return new StringBody(text, charset);
    }

    static HttpBody<ByteBuffer> ofBytes(byte[] binary) {
        return new BufferBody(ByteBuffer.wrap(binary, 0, binary.length));
    }

    static HttpBody<ByteBuffer> ofBytes(byte[] binary, int offset, int length) {
        return new BufferBody(ByteBuffer.wrap(binary, offset, length));
    }

    static HttpBody<ByteBuffer> ofBuffer(ByteBuffer buffer) {
        return new BufferBody(buffer);
    }

    static HttpBody<InputStream> ofStream(InputStream inputStream) {
        return new StreamBody(inputStream);
    }

    static HttpBody<Map<String, String>> ofFormData(Map<String, String> text) {
        return new FormBody(text, StandardCharsets.UTF_8);
    }
}
