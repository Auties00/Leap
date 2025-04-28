package it.auties.leap.http.exchange;

import java.nio.charset.StandardCharsets;

public final class HttpMethod {
    private static final HttpMethod CONNECT = new HttpMethod("CONNECT");
    private static final HttpMethod GET = new HttpMethod("GET");
    private static final HttpMethod POST = new HttpMethod("POST");
    private static final HttpMethod DELETE = new HttpMethod("DELETE");
    private static final HttpMethod HEAD = new HttpMethod("HEAD");
    private static final HttpMethod PUT = new HttpMethod("PUT");

    private final String name;
    private final byte[] encodedName;

    public HttpMethod(String name) {
        this.name = name;
        this.encodedName = name.getBytes(StandardCharsets.US_ASCII);
    }

    public static HttpMethod connect() {
        return CONNECT;
    }

    public static HttpMethod get() {
        return GET;
    }

    public static HttpMethod post() {
        return POST;
    }

    public static HttpMethod delete() {
        return DELETE;
    }

    public static HttpMethod head() {
        return HEAD;
    }

    public static HttpMethod put() {
        return PUT;
    }

    public static HttpMethod of(String token) {
        var encoded = new char[token.length()];
        for (int i = 0; i < encoded.length; i++) {
            var c = token.charAt(i);
            if (c > 255 || !Character.isAlphabetic(c)) {
                throw new IllegalArgumentException("Invalid HTTP method: " + token);
            }
            encoded[i] = Character.toUpperCase(c);
        }
        return new HttpMethod(new String(encoded));
    }

    public String name() {
        return name;
    }

    public byte[] encodedName() {
        return encodedName;
    }
}
