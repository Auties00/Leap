package it.auties.leap.http.exchange.request;

import it.auties.leap.http.exchange.body.HttpBody;
import it.auties.leap.http.exchange.HttpMethod;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

public sealed interface HttpRequestBuilder {
    final class Method implements HttpRequestBuilder {
        public <T> URI<T> connect() {
            return method(HttpMethod.connect(), null);
        }
        
        public <T> URI<T> get() {
            return method(HttpMethod.get(), null);
        }

        public <T> URI<T> delete() {
            return method(HttpMethod.delete(), null);
        }

        public <T> URI<T> head() {
            return method(HttpMethod.head(), null);
        }

        public <T> URI<T> post() {
            return method(HttpMethod.post(), null);
        }

        public <T> URI<T> post(HttpBody<T> body) {
            return method(HttpMethod.post(), body);
        }

        public <T> URI<T> put(HttpBody<T> body) {
            return method(HttpMethod.put(), body);
        }
        
        public <T> URI<T> method(HttpMethod method, HttpBody<T> body) {
            Objects.requireNonNull(method, "Expected a method");
            return new URI<>(method, Objects.requireNonNullElse(body, HttpBody.empty()));
        }
    }

    final class URI<T> implements HttpRequestBuilder {
        private final HttpMethod method;
        private final HttpBody<T> body;
        private URI(HttpMethod method, HttpBody<T> body) {
            this.method = method;
            this.body = body;
        }

        public Options<T> uri(java.net.URI uri) {
            Objects.requireNonNull(uri, "Expected a URI");
            return new Options<>(method, body, uri);
        }
    }

    final class Options<T> implements HttpRequestBuilder {
        private final HttpMethod method;
        private final HttpBody<T> body;
        private final java.net.URI uri;
        private final Map<String, Object> headers;
        private Duration timeout;

        private Options(HttpMethod method, HttpBody<T> body, java.net.URI uri) {
            this.method = method;
            this.body = body;
            this.uri = uri;
            this.headers = new HashMap<>();
            this.timeout = HttpRequest.DEFAULT_REQUEST_TIMEOUT;
        }

        public Options<T> headers(Map<String, ?> headers) {
            Objects.requireNonNull(headers, "Invalid headers");
            this.headers.putAll(headers);
            return this;
        }

        public Options<T> header(String key, String value) {
            Objects.requireNonNull(key, "Invalid header");
            this.headers.put(key, value);
            return this;
        }

        public Options<T> timeout(Duration timeout) {
            Objects.requireNonNull(timeout, "Invalid timeout");
            this.timeout = timeout;
            return this;
        }

        public HttpRequest<T> build() {
            return new HttpRequest<>(
                    method,
                    body,
                    uri,
                    headers,
                    Objects.requireNonNullElse(timeout, HttpRequest.DEFAULT_REQUEST_TIMEOUT)
            );
        }
    }
}
