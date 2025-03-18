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
import java.util.Optional;
import java.util.OptionalInt;

public final class StringBody implements HttpBody<String> {
    public static HttpBodyDeserializer<String> deserializer(Charset charset) {
        return new Deserializer(charset);
    }

    private final String content;
    private final Charset charset;

    public StringBody(String content, Charset charset) {
        this.content = content;
        this.charset = charset;
    }

    @Override
    public Optional<String> content() {
        return Optional.of(content);
    }

    @Override
    public OptionalInt length() {
        return OptionalInt.of(content.length());
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        var encoder = charset.newEncoder();
        var result = encoder.encode(CharBuffer.wrap(content), buffer, true);
        try {
            result.throwException();
        } catch (CharacterCodingException exception) {
            throw new UncheckedIOException(exception);
        }
    }

    @Override
    public String toString() {
        return content;
    }

    private record Deserializer(Charset charset) implements HttpBodyDeserializer<String> {
        @Override
        public HttpBody<String> deserialize(HttpVersion version, HttpHeaders headers, ByteBuffer buffer) {
            return new StringBody(charset.decode(buffer).toString(), charset);
        }
    }
}
