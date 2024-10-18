package it.auties.leap;

import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.Flow;
import java.util.concurrent.Flow.Publisher;
import java.util.stream.Collectors;

@SuppressWarnings("unused")
public final class HttpRequest {
    private static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(30);

    private final String method;
    private final Body body;
    private URI uri;
    private final Map<String, String> headers;
    private final Duration timeout;
    private HttpRequest(String method, Body body, URI uri, Map<String, ?> headers, Duration timeout) {
        this.method = Objects.requireNonNull(method, "Missing HTTP method");
        this.body = body;
        this.uri = Objects.requireNonNull(uri, "Missing HTTP endpoint");
        this.headers = parseHeaders(headers);
        this.timeout = Objects.requireNonNullElse(timeout, DEFAULT_TIMEOUT);
    }

    private static Map<String, String> parseHeaders(Map<String, ?> headers) {
        if(headers == null) {
            return Map.of();
        }

        var results = new HashMap<String, String>();
        headers.forEach((key, value) -> results.put(key.toLowerCase(), value.toString()));
        return Collections.unmodifiableMap(results);
    }

    public static MethodBuilder builder() {
        return new MethodBuilder();
    }

    public String method() {
        return method;
    }

    public Optional<Body> body() {
        return Optional.ofNullable(body);
    }

    public URI uri() {
        return uri;
    }

    public Map<String, ?> headers() {
        return headers;
    }

    public Duration timeout() {
        return timeout;
    }

    void setUri(URI uri) {
        this.uri = uri;
    }

    public static final class MethodBuilder {
        private MethodBuilder() {

        }

        public URIBuilder get() {
            return method("GET", null);
        }

        public URIBuilder post(Body body) {
            return method("POST", body);
        }

        public URIBuilder put(Body body) {
            return method("PUT", body);
        }

        public URIBuilder delete() {
            return method("DELETE", null);
        }

        public URIBuilder head() {
            return method("HEAD", null);
        }

        public URIBuilder method(String method, Body body) {
            return new URIBuilder(method.toUpperCase().trim(), body);
        }
    }

    public static final class URIBuilder {
        private final String method;
        private final Body body;
        private URIBuilder(String method, Body body) {
            this.method = method;
            this.body = body;
        }

        public OptionsBuilder uri(URI uri) {
            return new OptionsBuilder(method, body, uri);
        }
    }

    public static final class OptionsBuilder {
        private final String method;
        private final Body body;
        private final URI uri;
        private final Map<String, Object> headers;
        private Duration timeout;

        private OptionsBuilder(String method, Body body, URI uri) {
            this.method = method;
            this.body = body;
            this.uri = uri;
            this.headers = new HashMap<>();
            this.timeout = DEFAULT_TIMEOUT;
        }

        public OptionsBuilder headers(Map<String, ?> headers) {
            Objects.requireNonNull(headers, "Invalid headers");
            this.headers.putAll(headers);
            return this;
        }

        public OptionsBuilder header(String key, String value) {
            Objects.requireNonNull(key, "Invalid header");
            this.headers.put(key, value);
            return this;
        }

        public OptionsBuilder timeout(Duration timeout) {
            Objects.requireNonNull(timeout, "Invalid timeout");
            this.timeout = timeout;
            return this;
        }

        public HttpRequest build() {
            return new HttpRequest(method, body, uri, headers, timeout);
        }
    }

    public abstract static class Body implements Publisher<ByteBuffer> {
        public abstract OptionalInt length();

        public static Body ofString(String text) {
            return new Full(StandardCharsets.UTF_8.encode(text));
        }

        public static Body ofString(String text, Charset charset) {
            return new Full(charset.encode(text));
        }

        public static Body ofBytes(byte[] binary) {
            return new Full(ByteBuffer.wrap(binary, 0, binary.length));
        }

        public static Body ofBytes(byte[] binary, int offset, int length) {
            return new Full(ByteBuffer.wrap(binary, offset, length));
        }

        public static Body ofBuffer(ByteBuffer buffer) {
            return new Full(buffer);
        }

        public static Body ofForm(Map<String, ?> text) {
            var body = text.entrySet()
                    .stream()
                    .map(entry -> entry.getKey() + "=" + entry.getValue())
                    .collect(Collectors.joining("&"));
            return new Full(StandardCharsets.UTF_8.encode(body));
        }

        private static final class Full extends Body {
            private final ByteBuffer buffer;
            private Full(ByteBuffer buffer) {
                this.buffer = buffer;
            }

            @Override
            public OptionalInt length() {
                return OptionalInt.of(buffer.remaining());
            }

            @Override
            public void subscribe(Flow.Subscriber<? super ByteBuffer> subscriber) {
                subscriber.onNext(buffer);
                subscriber.onComplete();
            }
        }

        private static final class Stream extends Body {
            private Stream() {

            }

            @Override
            public OptionalInt length() {
                return OptionalInt.empty();
            }

            @Override
            public void subscribe(Flow.Subscriber<? super ByteBuffer> subscriber) {

            }
        }
    }
}
