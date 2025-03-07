package it.auties.leap.http.exchange.response;

import it.auties.leap.http.HttpVersion;
import it.auties.leap.http.exchange.body.HttpBody;

import java.nio.ByteBuffer;
import java.util.Objects;

public final class HttpResponse<T> {
    private final HttpResponseStatus status;
    private final HttpBody<T> body;

    HttpResponse(HttpResponseStatus status, HttpBody<T> body) {
        this.status = status;
        this.body = body;
    }

    public static <T> HttpResponseBuilder<T> newBuilder() {
        return new HttpResponseBuilder<>();
    }

    public HttpResponseStatus status() {
        return status;
    }

    public HttpBody<T> body() {
        return body;
    }

    public void serialize(HttpVersion version, ByteBuffer buffer) {

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
