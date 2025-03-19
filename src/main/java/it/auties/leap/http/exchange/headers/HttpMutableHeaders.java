package it.auties.leap.http.exchange.headers;

import java.util.*;

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
        backing.compute(key, (_, values) -> {
            if(values != null) {
                if(value != null) {
                    values.add(value.toString());
                }
                return values;
            }

            var newValues = new ArrayList<String>();
            if(value != null) {
                newValues.add(value.toString());
            }
            return newValues;
        });
    }

    public void put(Map<String, ?> headers) {
        headers.forEach((key, value) -> {
            var values = switch (value) {
                case null -> List.<String>of();
                case List<?> entries -> entries.stream()
                        .map(Object::toString)
                        .filter(Objects::nonNull)
                        .toList();
                default -> Collections.singletonList(value.toString());
            };
            backing.put(key, values);
        });
    }

    public void put(HttpHeaders headers) {
        backing.putAll(headers.backing);
    }

    public HttpHeaders toImmutableHeaders() {
        return new HttpHeaders(backing);
    }
}
