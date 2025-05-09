package it.auties.leap.tls.alert;

public class TlsAlert extends RuntimeException {
    private final TlsAlertLevel level;
    private final TlsAlertType type;

    public TlsAlert(String message, TlsAlertLevel level, TlsAlertType type) {
        this(message, null, level, type);
    }

    public TlsAlert(String message, Throwable throwable, TlsAlertLevel level, TlsAlertType type) {
        super(message, throwable);
        this.level = level;
        this.type = type;
    }

    public TlsAlertLevel level() {
        return level;
    }

    public TlsAlertType type() {
        return type;
    }
}
