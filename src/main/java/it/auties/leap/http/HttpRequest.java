package it.auties.leap.http;

import java.net.URI;
import java.time.Duration;
import java.util.*;

@SuppressWarnings("unused")
public final class HttpRequest {
    static final Duration DEFAULT_REQUEST_TIMEOUT = Duration.ofSeconds(300);

    private final String method;
    private final HttpRequestBody body;
    private final URI uri;
    private final Map<String, String> headers;
    private final Duration timeout;
    HttpRequest(String method, HttpRequestBody body, URI uri, Map<String, ?> headers, Duration timeout) {
        this.method = Objects.requireNonNull(method, "Missing HTTP method");
        this.body = body;
        this.uri = Objects.requireNonNull(uri, "Missing HTTP endpoint");
        this.headers = parseHeaders(headers);
        this.timeout = Objects.requireNonNullElse(timeout, DEFAULT_REQUEST_TIMEOUT);
    }

    private static Map<String, String> parseHeaders(Map<String, ?> headers) {
        if(headers == null) {
            return Map.of();
        }

        var results = new HashMap<String, String>();
        headers.forEach((key, value) -> results.put(key.toLowerCase(), value.toString()));
        return Collections.unmodifiableMap(results);
    }

    public static HttpRequestBuilder newBuilder() {
        return new HttpRequestBuilder.Method();
    }

    public String method() {
        return method;
    }

    public Optional<HttpRequestBody> body() {
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
}
