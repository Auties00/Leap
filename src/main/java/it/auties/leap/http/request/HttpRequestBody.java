package it.auties.leap.http.request;

import it.auties.leap.http.request.implementation.EmptyRequestBody;
import it.auties.leap.http.request.implementation.StaticRequestBody;
import it.auties.leap.http.request.implementation.StreamRequestBody;

import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.OptionalInt;
import java.util.stream.Collectors;

public interface HttpRequestBody {
    void serialize(ByteBuffer buffer);
    OptionalInt length();

    static HttpRequestBody empty() {
        return EmptyRequestBody.instance();
    }

    static HttpRequestBody ofString(String text) {
        return new StaticRequestBody(StandardCharsets.UTF_8.encode(text));
    }

    static HttpRequestBody ofString(String text, Charset charset) {
        return new StaticRequestBody(charset.encode(text));
    }

    static HttpRequestBody ofBytes(byte[] binary) {
        return new StaticRequestBody(ByteBuffer.wrap(binary, 0, binary.length));
    }

    static HttpRequestBody ofBytes(byte[] binary, int offset, int length) {
        return new StaticRequestBody(ByteBuffer.wrap(binary, offset, length));
    }

    static HttpRequestBody ofBuffer(ByteBuffer buffer) {
        return new StaticRequestBody(buffer);
    }

    static HttpRequestBody ofStream(InputStream inputStream, int chunkSize) {
        return new StreamRequestBody(inputStream, chunkSize);
    }

    static HttpRequestBody ofForm(Map<String, ?> text) {
        var body = text.entrySet()
                .stream()
                .map(entry -> entry.getKey() + "=" + entry.getValue())
                .collect(Collectors.joining("&"));
        return new StaticRequestBody(StandardCharsets.UTF_8.encode(body));
    }
}
