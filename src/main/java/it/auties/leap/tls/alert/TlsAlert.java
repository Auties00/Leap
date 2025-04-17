package it.auties.leap.tls.alert;

import java.net.URI;
import java.util.Optional;

public class TlsAlert extends RuntimeException {
    private final URI source;
    private final String section;
    private final TlsAlertLevel level;
    private final TlsAlertType type;

    public TlsAlert(String message, URI source, String section, TlsAlertLevel level, TlsAlertType type) {
        super(message);
        this.source = source;
        this.section = section;
        this.level = level;
        this.type = type;
    }

    public TlsAlert(String message, TlsAlertLevel level, TlsAlertType type) {
        this(message, null, null, level, type);
    }

    public Optional<URI> source() {
        return Optional.ofNullable(source);
    }

    public Optional<String> section() {
        return Optional.ofNullable(section);
    }

    public TlsAlertLevel level() {
        return level;
    }

    public TlsAlertType type() {
        return type;
    }
}
