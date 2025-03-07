package it.auties.leap.http.exchange.response;

import it.auties.leap.http.exchange.body.HttpBody;
import it.auties.leap.http.exchange.headers.HttpHeaders;

import java.util.Objects;

public final class HttpResponseBuilder<T> {
    private HttpResponseStatus status;
    private HttpHeaders headers;
    private HttpBody<T> body;

    public HttpResponseBuilder<T> status(HttpResponseStatus status) {
        this.status = status;
        return this;
    }

    public HttpResponseBuilder<T> headers(HttpHeaders headers) {
        this.headers = headers;
        return this;
    }

    public HttpResponseBuilder<T> body(HttpBody<T> body) {
        this.body = body;
        return this;
    }

    public HttpResponse<T> build() {
        return new HttpResponse<>(
                Objects.requireNonNullElse(status, HttpResponseStatus.ok()),
                Objects.requireNonNullElse(headers, HttpHeaders.empty()),
                Objects.requireNonNullElse(body, HttpBody.empty())
        );
    }
}
