package it.auties.leap.http.exchange.response;

import it.auties.leap.http.HttpVersion;
import it.auties.leap.http.exchange.HttpExchange;
import it.auties.leap.http.exchange.body.HttpBody;
import it.auties.leap.http.exchange.body.HttpBodyDeserializer;
import it.auties.leap.http.exchange.headers.HttpHeaders;
import it.auties.leap.http.exchange.serialization.AsyncHttpSerializer;
import it.auties.leap.socket.async.AsyncSocketIO;
import it.auties.leap.socket.blocking.BlockingSocketIO;

import java.nio.ByteBuffer;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;

public final class HttpResponse<T> implements HttpExchange<T> {
    private final HttpVersion version;
    private final HttpResponseStatus status;
    private final HttpHeaders headers;
    private final HttpBody<T> body;

    HttpResponse(HttpVersion version, HttpResponseStatus status, HttpHeaders headers, HttpBody<T> body) {
        this.version = version;
        this.status = status;
        this.headers = headers;
        this.body = body;
    }

    public static <T> HttpResponse<T> deserializeBlocking(BlockingSocketIO io, HttpBodyDeserializer<T> deserializer) {
        throw new UnsupportedOperationException();
    }

    public static <T> CompletableFuture<HttpResponse<T>> deserializeAsync(AsyncSocketIO io, HttpBodyDeserializer<T> deserializer) {
        var parser = new AsyncHttpSerializer<T>();
        return parser.decode(io, deserializer);
    }

    public static <T> HttpResponseBuilder<T> builder() {
        return new HttpResponseBuilder<>();
    }

    public HttpVersion version() {
        return version;
    }

    public HttpResponseStatus status() {
        return status;
    }

    @Override
    public HttpHeaders headers() {
        return headers;
    }

    @Override
    public HttpBody<T> body() {
        return body;
    }

    @Override
    public void serialize(HttpVersion version, ByteBuffer buffer) {

    }

    @Override
    public int length(HttpVersion version) {
        return 0;
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof HttpResponse<?> that
                && Objects.equals(status, that.status)
                && Objects.equals(body, that.body);
    }

    @Override
    public int hashCode() {
        return Objects.hash(status, body);
    }

    @Override
    public String toString() {
        return "HttpResponse[" +
                "status=" + status + ", " +
                "body=" + body + ']';
    }
}
