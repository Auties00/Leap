package it.auties.leap.http;

import java.nio.charset.StandardCharsets;

public enum HttpVersion {
    HTTP_1_1("HTTP/1.1".getBytes(StandardCharsets.US_ASCII)),
    HTTP_2("HTTP/2".getBytes(StandardCharsets.US_ASCII)),
    HTTP_3("HTTP/3".getBytes(StandardCharsets.US_ASCII));

    private final byte[] encodedName;
    HttpVersion(byte[] encodedName) {
        this.encodedName = encodedName;
    }

    public byte[] encodedName() {
        return encodedName;
    }
}
