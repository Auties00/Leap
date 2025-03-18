package it.auties.leap.http.exchange.headers;

import java.util.Map;
import java.util.Objects;

public final class HttpMutableHeaders extends HttpHeaders {
    HttpMutableHeaders() {

    }

    public static HttpMutableHeaders newMutableHeaders() {
        return new HttpMutableHeaders();
    }

    public static HttpMutableHeaders newMutableHeaders(HttpHeaders headers) {
        var instance = new HttpMutableHeaders();
        instance.put(headers);
        return instance;
    }

    public void put(String key, Object value) {
        Objects.requireNonNull(key, "Expected a key");
        Objects.requireNonNull(value, "Expected a value");
        backing.put(key, value);
    }

    public void put(Map<String, ?> headers) {
        headers.forEach((key, value) -> backing.put(key, value == null ? "" : value.toString()));
    }

    public void put(HttpHeaders headers) {
        backing.putAll(headers.backing);
    }

    public HttpHeaders toImmutableHeaders() {
        return new HttpHeaders(backing);
    }
}
