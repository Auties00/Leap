package it.auties.leap.tls;

import it.auties.leap.tls.property.TlsProperty;

import java.net.URI;

// TODO: Offer more named constructors
public class TlsException extends RuntimeException {
    public TlsException(String message) {
        super(message);
    }

    public TlsException(String message, Throwable cause) {
        super(message, cause);
    }

    public TlsException(String message, URI source) {
        super("%s (source at %s)".formatted(message, source));
    }

    public TlsException(String message, URI source, String section) {
        super("%s (section %s at %s)".formatted(message, section, source));
    }

    public static TlsException stub() {
        return new TlsException("Stub");
    }

    public static TlsException noSecureRandom() {
        throw new TlsException("Missing strong secure random implementation");
    }

    public static TlsException noNegotiableProperty(TlsProperty<?, ?> property) {
        throw new TlsException("Missing negotiable property: " + property.id());
    }

    public static TlsException noNegotiatedProperty(TlsProperty<?, ?> property) {
        throw new TlsException("Missing negotiated property: " + property.id());
    }

    public static TlsException noModeSelected() {
       return new TlsException("No mode was selected");
    }

    public static TlsException noRemoteConnectionState() {
        return new TlsException("No remote connection state was created");
    }

    public static TlsException noLocalKeyExchange() {
        return new TlsException("No local key exchange was created");
    }

    public static TlsException noRemoteKeyExchange() {
        return new TlsException("No remote key exchange was created");
    }

    public static TlsException noSupportedFiniteField() {
        return new TlsException("No supported group is a finite field");
    }

    public static TlsException noSupportedEllipticCurve() {
        return new TlsException("No supported group is an elliptic curve");
    }

    public static TlsException remoteKeyExchangeTypeMismatch(String expected) {
        return new TlsException("Expected remote key exchange to have type " + expected);
    }

    public static TlsException malformedRemoteKeyExchange() {
        return new TlsException("Malformed remote key exchange");
    }

    public static TlsException preMasterSecretError(Throwable cause) {
        return new TlsException("Cannot generate pre master secret", cause);
    }
}
