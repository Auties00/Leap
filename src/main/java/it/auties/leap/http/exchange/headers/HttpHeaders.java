package it.auties.leap.http.exchange.headers;

import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;
import java.util.function.BiConsumer;

public sealed class HttpHeaders permits HttpMutableHeaders {
    private static final HttpHeaders EMPTY = new HttpHeaders();
    protected final Map<String, String> backing;
    HttpHeaders() {
        this.backing = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
    }

    HttpHeaders(Map<String, String> backing) {
        this.backing = backing;
    }

    public static HttpHeaders empty() {
        return EMPTY;
    }

    public static HttpHeaders newImmutableHeaders() {
        return new HttpHeaders();
    }

    public static HttpHeaders newImmutableHeaders(HttpHeaders headers) {
        var instance = new HttpHeaders();
        instance.backing.putAll(headers.backing);
        return instance;
    }

    public Optional<String> get(String key) {
        return Optional.ofNullable(backing.get(key));
    }

    public void forEach(BiConsumer<? super String, ? super String> action) {
        backing.forEach(action);
    }

    public int size() {
        return backing.size();
    }
}
