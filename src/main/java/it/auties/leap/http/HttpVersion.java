package it.auties.leap.http;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

public enum HttpVersion {
    HTTP_1_1("HTTP/1.1".getBytes(StandardCharsets.US_ASCII)),
    HTTP_2("HTTP/2".getBytes(StandardCharsets.US_ASCII)),
    HTTP_3("HTTP/3".getBytes(StandardCharsets.US_ASCII));

    private final byte[] encodedName;
    HttpVersion(byte[] encodedName) {
        this.encodedName = encodedName;
    }

    public static Optional<HttpVersion> of(int major, int minor) {
        if(major == 1 && minor == 1) {
            return Optional.of(HTTP_1_1);
        }else if(major == 2 && minor == 0) {
            return Optional.of(HTTP_2);
        }else if(major == 3 && minor == 0) {
            return Optional.of(HTTP_3);
        }else {
            return Optional.empty();
        }
    }

    public byte[] encodedName() {
        return encodedName;
    }
}
