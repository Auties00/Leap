package it.auties.leap.http;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

public sealed interface HttpRequestBuilder {
    final class Method implements HttpRequestBuilder{
        public URI get() {
            return method("GET", null);
        }

        public URI post(HttpRequestBody body) {
            return method("POST", body);
        }

        public URI put(HttpRequestBody body) {
            return method("PUT", body);
        }

        public URI delete() {
            return method("DELETE", null);
        }

        public URI head() {
            return method("HEAD", null);
        }

        public URI method(String method, HttpRequestBody body) {
            return new URI(method.toUpperCase().trim(), body);
        }
    }

    final class URI implements HttpRequestBuilder {
        private final String method;
        private final HttpRequestBody body;
        private URI(String method, HttpRequestBody body) {
            this.method = method;
            this.body = body;
        }

        public Options uri(java.net.URI uri) {
            return new Options(method, body, uri);
        }
    }

    final class Options implements HttpRequestBuilder {
        private final String method;
        private final HttpRequestBody body;
        private final java.net.URI uri;
        private final Map<String, Object> headers;
        private Duration timeout;

        private Options(String method, HttpRequestBody body, java.net.URI uri) {
            this.method = method;
            this.body = body;
            this.uri = uri;
            this.headers = new HashMap<>();
            this.timeout = HttpRequest.DEFAULT_REQUEST_TIMEOUT;
        }

        public Options headers(Map<String, ?> headers) {
            Objects.requireNonNull(headers, "Invalid headers");
            this.headers.putAll(headers);
            return this;
        }

        public Options header(String key, String value) {
            Objects.requireNonNull(key, "Invalid header");
            this.headers.put(key, value);
            return this;
        }

        public Options timeout(Duration timeout) {
            Objects.requireNonNull(timeout, "Invalid timeout");
            this.timeout = timeout;
            return this;
        }

        public HttpRequest build() {
            return new HttpRequest(method, body, uri, headers, timeout);
        }
    }
}
