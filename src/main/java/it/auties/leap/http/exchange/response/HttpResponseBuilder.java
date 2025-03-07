package it.auties.leap.http.exchange.response;

import it.auties.leap.http.exchange.body.HttpBody;

import java.util.Objects;

public final class HttpResponseBuilder<T> {
    private HttpResponseStatus status;
    private HttpBody<T> body;

    public HttpResponseBuilder<T> status(HttpResponseStatus status) {
        this.status = status;
        return this;
    }

    public HttpResponseBuilder<T> body(HttpBody<T> body) {
        this.body = body;
        return this;
    }

    public HttpResponse<T> build() {
        return new HttpResponse<>(
                Objects.requireNonNullElse(status, HttpResponseStatus.ok()),
                Objects.requireNonNullElse(body, HttpBody.empty())
        );
    }
}
