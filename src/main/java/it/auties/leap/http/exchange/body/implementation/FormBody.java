package it.auties.leap.http.exchange.body.implementation;

import it.auties.leap.http.HttpVersion;
import it.auties.leap.http.exchange.body.HttpBody;
import it.auties.leap.http.exchange.body.HttpBodyDeserializer;
import it.auties.leap.http.exchange.headers.HttpHeaders;

import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.Map;
import java.util.OptionalInt;
import java.util.stream.Collectors;

public final class FormBody implements HttpBody<Map<String, String>> {
    public static HttpBodyDeserializer<Map<String, String>> deserializer(Charset charset) {
        return new Deserializer(charset);
    }

    private final Map<String, String> content;
    private final Charset charset;

    public FormBody(Map<String, String> content, Charset charset) {
        this.content = content;
        this.charset = charset;
    }

    @Override
    public Map<String, String> content() {
        return content;
    }

    @Override
    public OptionalInt length() {
        return OptionalInt.of(content.size());
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        var encoder = charset.newEncoder();
        var body = content.entrySet()
                .stream()
                .map(entry -> entry.getKey() + "=" + entry.getValue())
                .collect(Collectors.joining("&"));
        var result = encoder.encode(CharBuffer.wrap(body), buffer, true);
        try {
            result.throwException();
        } catch (CharacterCodingException exception) {
            throw new UncheckedIOException(exception);
        }
    }

    @Override
    public String toString() {
        return content.entrySet()
                .stream()
                .map(entry -> entry.getKey() + "=" + entry.getValue())
                .collect(Collectors.joining("&"));
    }

    private record Deserializer(Charset charset) implements HttpBodyDeserializer<Map<String, String>> {
        @Override
        public HttpBody<Map<String, String>> deserialize(HttpVersion version, HttpHeaders headers, ByteBuffer buffer) {
            var content = Arrays.stream(charset.decode(buffer)
                    .toString()
                    .split("&"))
                    .map(entry -> {
                        var entries = entry.split("=", 2);
                        var key = entries[0];
                        var value = entries.length != 2 ? "" : entries[1];
                        return Map.entry(key, value);
                    })
                    .collect(Collectors.toUnmodifiableMap(Map.Entry::getKey, Map.Entry::getValue));
            return new FormBody(content, charset);
        }
    }
}
