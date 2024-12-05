package it.auties.leap.http.decoder;

import java.util.Map;

enum HttpEncoding {
    CHUNKED,
    COMPRESS,
    GZIP,
    DEFLATE,
    UNKNOWN;

    private static final Map<String, HttpEncoding> VALUES = Map.of(
            "chunked", CHUNKED,
            "compress", COMPRESS,
            "gzip", GZIP,
            "deflate", DEFLATE
    );

    static HttpEncoding of(String value) {
        return VALUES.getOrDefault(value.toLowerCase().trim(), UNKNOWN);
    }
}
