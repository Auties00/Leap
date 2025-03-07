package it.auties.leap.http.exchange.headers;

import java.util.Map;

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
        backing.put(key, value == null ? "" : value.toString());
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
