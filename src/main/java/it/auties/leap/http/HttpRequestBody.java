package it.auties.leap.http;

import it.auties.leap.http.request.HttpEmptyRequestBody;
import it.auties.leap.http.request.HttpStaticRequestBody;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.OptionalInt;
import java.util.concurrent.Flow;
import java.util.stream.Collectors;

public interface HttpRequestBody extends Flow.Publisher<ByteBuffer> {
    OptionalInt length();

    static HttpRequestBody ofEmpty() {
        return HttpEmptyRequestBody.instance();
    }

    static HttpRequestBody ofString(String text) {
        return new HttpStaticRequestBody(StandardCharsets.UTF_8.encode(text));
    }

    static HttpRequestBody ofString(String text, Charset charset) {
        return new HttpStaticRequestBody(charset.encode(text));
    }

    static HttpRequestBody ofBytes(byte[] binary) {
        return new HttpStaticRequestBody(ByteBuffer.wrap(binary, 0, binary.length));
    }

    static HttpRequestBody ofBytes(byte[] binary, int offset, int length) {
        return new HttpStaticRequestBody(ByteBuffer.wrap(binary, offset, length));
    }

    static HttpRequestBody ofBuffer(ByteBuffer buffer) {
        return new HttpStaticRequestBody(buffer);
    }

    static HttpRequestBody ofForm(Map<String, ?> text) {
        var body = text.entrySet()
                .stream()
                .map(entry -> entry.getKey() + "=" + entry.getValue())
                .collect(Collectors.joining("&"));
        return new HttpStaticRequestBody(StandardCharsets.UTF_8.encode(body));
    }
}
