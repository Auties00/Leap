package it.auties.leap.http.exchange.request;

import it.auties.leap.http.HttpVersion;
import it.auties.leap.http.exchange.HttpExchange;
import it.auties.leap.http.exchange.HttpMethod;
import it.auties.leap.http.exchange.body.HttpBody;
import it.auties.leap.http.exchange.body.HttpBodyDeserializer;
import it.auties.leap.http.exchange.headers.HttpHeaders;
import it.auties.leap.http.exchange.serialization.HttpConstants;
import it.auties.leap.socket.async.AsyncSocketIO;
import it.auties.leap.socket.blocking.BlockingSocketIO;

import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;

@SuppressWarnings("unused")
public final class HttpRequest<T> implements HttpExchange<T> {
    static final Duration DEFAULT_REQUEST_TIMEOUT = Duration.ofSeconds(300);

    private final HttpMethod method;
    private final HttpBody<T> body;
    private final URI uri;
    private final HttpHeaders headers;
    private final Duration timeout;
    HttpRequest(HttpMethod method, HttpBody<T> body, URI uri, HttpHeaders headers, Duration timeout) {
        this.method = method;
        this.body = body;
        this.uri = uri;
        this.headers = headers;
        this.timeout = timeout;
    }

    public static <T> HttpRequest<T> deserializeBlocking(BlockingSocketIO io, HttpBodyDeserializer<T> deserializer) {
        throw new UnsupportedOperationException();
    }

    public static <T> CompletableFuture<HttpRequest<T>> deserializeAsync(AsyncSocketIO io, HttpBodyDeserializer<T> deserializer) {
        throw new UnsupportedOperationException();
    }

    public static <T> HttpRequestBuilder<T> newBuilder() {
        return new HttpRequestBuilder<>();
    }

    public HttpMethod method() {
        return method;
    }

    @Override
    public HttpBody<T> body() {
        return body;
    }

    public URI uri() {
        return uri;
    }

    @Override
    public HttpHeaders headers() {
        return headers;
    }

    public Duration timeout() {
        return timeout;
    }

    @Override
    public void serialize(HttpVersion version, ByteBuffer buffer) {
        buffer.put(method.encodedName());
        buffer.put((byte) HttpConstants.SPACE);
        buffer.put(normalizePath().getBytes(StandardCharsets.US_ASCII));
        buffer.put((byte) HttpConstants.SPACE);
        buffer.put(version.encodedName());

        headers.forEach((key, value) -> {
            buffer.put((byte) HttpConstants.CARRIAGE_RETURN);
            buffer.put((byte) HttpConstants.LINE_FEED);
            buffer.put(key.getBytes(StandardCharsets.US_ASCII));
            buffer.put((byte) HttpConstants.HEADER_SEPARATOR);
            buffer.put((byte) HttpConstants.SPACE);
            buffer.put(value.toString().getBytes(StandardCharsets.US_ASCII));
        });

        buffer.put((byte) HttpConstants.CARRIAGE_RETURN);
        buffer.put((byte) HttpConstants.LINE_FEED);

        body.serialize(buffer);

        buffer.put((byte) HttpConstants.CARRIAGE_RETURN);
        buffer.put((byte) HttpConstants.LINE_FEED);
    }

    private String normalizePath() {
        var path = uri.getPath();
        if(!path.endsWith("/")) {
            path += "/";
        }
        return path;
    }

    @Override
    public int length(HttpVersion version) {
        return 0;
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof HttpRequest<?> that
                && Objects.equals(method, that.method)
                && Objects.equals(body, that.body)
                && Objects.equals(uri, that.uri)
                && Objects.equals(headers, that.headers)
                && Objects.equals(timeout, that.timeout);
    }

    @Override
    public int hashCode() {
        return Objects.hash(method, body, uri, headers, timeout);
    }
}
