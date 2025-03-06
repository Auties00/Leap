package it.auties.leap.http.request;

import it.auties.leap.http.HttpMethod;
import it.auties.leap.http.HttpVersion;
import it.auties.leap.http.implementation.HttpConstants;

import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;

@SuppressWarnings("unused")
public final class HttpRequest {
    static final Duration DEFAULT_REQUEST_TIMEOUT = Duration.ofSeconds(300);

    private final HttpMethod method;
    private final HttpRequestBody body;
    private final URI uri;
    private final Map<String, Object> headers;
    private final Duration timeout;
    HttpRequest(HttpMethod method, HttpRequestBody body, URI uri, Map<String, Object> headers, Duration timeout) {
        this.method = method;
        this.body = body;
        this.uri = uri;
        this.headers = headers;
        this.timeout = timeout;
    }

    public static HttpRequestBuilder newBuilder() {
        return new HttpRequestBuilder.Method();
    }

    public HttpMethod method() {
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

    // TODO: Switch serialization based on version
    public void serialize(HttpVersion version, ByteBuffer buffer) {
        buffer.put(method.encodedName());
        buffer.put(HttpConstants.SPACE);
        buffer.put(version.encodedName());

        for(var header : headers.entrySet()) {
            buffer.put(HttpConstants.NEW_LINE);
            buffer.put(header.getKey().getBytes(StandardCharsets.US_ASCII));
            buffer.put(HttpConstants.HEADER_SEPARATOR);
            var value = header.getValue();
            if(value != null) {
                buffer.put(value.toString().getBytes(StandardCharsets.US_ASCII));
            }
        }

        buffer.put(HttpConstants.NEW_LINE);

        body.serialize(buffer);

        buffer.put(HttpConstants.NEW_LINE);
    }
}
