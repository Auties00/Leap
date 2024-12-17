package it.auties.leap.tls.exception;

import java.net.URI;

// TODO: Split this exception
public class TlsException extends RuntimeException {
    public TlsException(String message) {
        super(message);
    }

    public TlsException(String message, Throwable cause) {
        super(message, cause);
    }

    public TlsException(String message, URI source, String section) {
        super("%s (section %s at %s)".formatted(message, section, source));
    }
}