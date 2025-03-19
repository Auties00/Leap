package it.auties.leap.http.exchange.request;

import it.auties.leap.http.exchange.HttpMethod;
import it.auties.leap.http.exchange.body.HttpBody;
import it.auties.leap.http.exchange.headers.HttpHeaders;
import it.auties.leap.http.exchange.headers.HttpMutableHeaders;

import java.net.URI;
import java.time.Duration;
import java.util.Map;
import java.util.Objects;

public final class HttpRequestBuilder<T> {
    private static final String DEFAULT_USER_AGENT = "Java/" + System.getProperty("java.version");

    private HttpMethod method;
    private HttpBody<T> body;
    private URI uri;
    private Duration timeout;
    private final HttpMutableHeaders headers;

    HttpRequestBuilder() {
        this.headers = HttpMutableHeaders.newMutableHeaders();
    }

    public HttpRequestBuilder<T> connect() {
        return method(HttpMethod.connect(), null);
    }

    public HttpRequestBuilder<T> get() {
        return method(HttpMethod.get(), null);
    }

    public HttpRequestBuilder<T> delete() {
        return method(HttpMethod.delete(), null);
    }

    public HttpRequestBuilder<T> head() {
        return method(HttpMethod.head(), null);
    }

    public HttpRequestBuilder<T> post() {
        return method(HttpMethod.post(), null);
    }

    public HttpRequestBuilder<T> post(HttpBody<T> body) {
        return method(HttpMethod.post(), body);
    }

    public HttpRequestBuilder<T> put(HttpBody<T> body) {
        return method(HttpMethod.put(), body);
    }

    public HttpRequestBuilder<T> method(HttpMethod method, HttpBody<T> body) {
        this.method = Objects.requireNonNull(method, "Expected a method");
        this.body = Objects.requireNonNullElse(body, HttpBody.empty());
        return this;
    }

    public HttpRequestBuilder<T> uri(URI uri) {
        Objects.requireNonNull(uri, "Expected a URI");
        this.uri = uri;
        return this;
    }

    public HttpRequestBuilder<T> headers(Map<String, ?> headers) {
        Objects.requireNonNull(headers, "Invalid headers");
        this.headers.put(headers);
        return this;
    }

    public HttpRequestBuilder<T> headers(HttpHeaders headers) {
        Objects.requireNonNull(headers, "Invalid headers");
        this.headers.put(headers);
        return this;
    }

    public HttpRequestBuilder<T> header(String key, Object value) {
        Objects.requireNonNull(key, "Invalid header");
        if(value != null) {
            this.headers.put(key, value);
        }
        return this;
    }

    public HttpRequestBuilder<T> timeout(Duration timeout) {
        Objects.requireNonNull(timeout, "Invalid timeout");
        this.timeout = timeout;
        return this;
    }

    public HttpRequest<T> build() {
        if(headers.host().isEmpty()) {
            headers.put("Host", uri.getHost());
        }

        if(headers.connection().isEmpty()) {
            headers.put("Connection", "close");
        }

        if(headers.userAgent().isEmpty()) {
            headers.put("User-Agent", DEFAULT_USER_AGENT);
        }

        return new HttpRequest<>(
                method,
                body,
                uri,
                headers.toImmutableHeaders(),
                Objects.requireNonNullElse(timeout, HttpRequest.DEFAULT_REQUEST_TIMEOUT)
        );
    }
}
