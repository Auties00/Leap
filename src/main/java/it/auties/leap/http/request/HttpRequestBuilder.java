package it.auties.leap.http.request;

import it.auties.leap.http.HttpMethod;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

public sealed interface HttpRequestBuilder {
    final class Method implements HttpRequestBuilder{
        public URI get() {
            return method(HttpMethod.get(), null);
        }

        public URI post(HttpRequestBody body) {
            return method(HttpMethod.post(), body);
        }

        public URI put(HttpRequestBody body) {
            return method(HttpMethod.put(), body);
        }

        public URI delete() {
            return method(HttpMethod.delete(), null);
        }

        public URI head() {
            return method(HttpMethod.head(), null);
        }

        public URI method(HttpMethod method, HttpRequestBody body) {
            return new URI(method, body);
        }
    }

    final class URI implements HttpRequestBuilder {
        private final HttpMethod method;
        private final HttpRequestBody body;
        private URI(HttpMethod method, HttpRequestBody body) {
            this.method = method;
            this.body = body;
        }

        public Options uri(java.net.URI uri) {
            return new Options(method, body, uri);
        }
    }

    final class Options implements HttpRequestBuilder {
        private final HttpMethod method;
        private final HttpRequestBody body;
        private final java.net.URI uri;
        private final Map<String, Object> headers;
        private Duration timeout;

        private Options(HttpMethod method, HttpRequestBody body, java.net.URI uri) {
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
            return new HttpRequest(
                    Objects.requireNonNull(method, "Required method"),
                    Objects.requireNonNullElse(body, HttpRequestBody.empty()),
                    Objects.requireNonNull(uri, "Required uri"),
                    headers,
                    Objects.requireNonNullElse(timeout, HttpRequest.DEFAULT_REQUEST_TIMEOUT)
            );
        }
    }
}
