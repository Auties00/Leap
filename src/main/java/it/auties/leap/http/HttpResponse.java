package it.auties.leap.http;

import java.util.Objects;
import java.util.Optional;

@SuppressWarnings("unused")
public final class HttpResponse<T> {
    private final int statusCode;
    private final T body;

    public HttpResponse(int statusCode, T body) {
        this.statusCode = statusCode;
        this.body = body;
    }

    public int statusCode() {
        return statusCode;
    }

    public Optional<T> body() {
        return Optional.ofNullable(body);
    }

    @Override
    public boolean equals(Object obj) {
        return obj instanceof HttpResponse<?> that
                && that.statusCode == statusCode
                && Objects.equals(that.body, body);
    }

    @Override
    public int hashCode() {
        return Objects.hash(statusCode, body);
    }

    @Override
    public String toString() {
        return "HttpResponse[" +
                "statusCode=" + statusCode + ", " +
                "body=" + body + ']';
    }
}
