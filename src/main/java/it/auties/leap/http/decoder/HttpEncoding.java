package it.auties.leap.http.decoder;

import java.util.Map;

enum HttpEncoding {
    CHUNKED,
    COMPRESS,
    GZIP,
    DEFLATE,
    UNKNOWN;

    private static final Map<String, HttpEncoding> CASES = Map.of(
            "chunked", CHUNKED,
            "compress", COMPRESS,
            "gzip", GZIP,
            "deflate", DEFLATE
    );

    static HttpEncoding of(String value) {
        return CASES.getOrDefault(value.toLowerCase().trim(), UNKNOWN);
    }
}
