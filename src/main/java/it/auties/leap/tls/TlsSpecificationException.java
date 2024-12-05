package it.auties.leap.tls;

import java.net.URI;

public class TlsSpecificationException extends RuntimeException {
    public TlsSpecificationException(String message) {
        super(message);
    }

    public TlsSpecificationException(String message, URI source, String section) {
        super("%s (section %s at %s)".formatted(message, section, source));
    }
}
