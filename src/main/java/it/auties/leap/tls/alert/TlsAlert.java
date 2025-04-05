package it.auties.leap.tls.alert;

import it.auties.leap.tls.property.TlsProperty;

import java.net.URI;

// TODO: Offer more named constructors
public class TlsAlert extends RuntimeException {
    public TlsAlert(String message) {
        super(message);
    }

    public TlsAlert(String message, Throwable cause) {
        super(message, cause);
    }

    public TlsAlert(String message, URI source) {
        super("%s (source at %s)".formatted(message, source));
    }

    public TlsAlert(String message, URI source, String section) {
        super("%s (section %s at %s)".formatted(message, section, source));
    }

    public static TlsAlert stub() {
        return new TlsAlert("Stub");
    }

    public static TlsAlert noSecureRandom() {
        throw new TlsAlert("Missing strong secure random implementation");
    }

    public static TlsAlert noNegotiableProperty(TlsProperty<?, ?> property) {
        throw new TlsAlert("Missing negotiable property: " + property.id());
    }

    public static TlsAlert noNegotiatedProperty(TlsProperty<?, ?> property) {
        throw new TlsAlert("Missing negotiated property: " + property.id());
    }

    public static TlsAlert noRemoteConnectionState() {
        return new TlsAlert("No remote connection state was created");
    }

    public static TlsAlert noLocalKeyExchange() {
        return new TlsAlert("No local key exchange was created");
    }

    public static TlsAlert noRemoteKeyExchange() {
        return new TlsAlert("No remote key exchange was created");
    }

    public static TlsAlert noSupportedFiniteField() {
        return new TlsAlert("No supported group is a finite field");
    }

    public static TlsAlert noSupportedEllipticCurve() {
        return new TlsAlert("No supported group is an elliptic curve");
    }

    public static TlsAlert keyExchangeTypeMismatch(String expected) {
        return new TlsAlert("Expected key exchange to have type " + expected);
    }

    public static TlsAlert malformedRemoteKeyExchange() {
        return new TlsAlert("Malformed remote key exchange");
    }

    public static TlsAlert preMasterSecretError(Throwable cause) {
        return new TlsAlert("Cannot generate pre master secret", cause);
    }

    public static TlsAlert destroyedSecret() {
        return new TlsAlert("Tried to access a destroyed secret");
    }

    public static TlsAlert noCertificatesProvider() {
        return new TlsAlert("No certificates provider");
    }

    public static TlsAlert certificateError(Throwable cause) {
        return new TlsAlert("Cannot encode certificate", cause);
    }

    public static TlsAlert noLocalCipher() {
        return new TlsAlert("No local cipher");
    }

    public static TlsAlert noRemoteCipher() {
        return new TlsAlert("No remote cipher");
    }

    public static TlsAlert noKeyPairSelected() {
        return new TlsAlert("No key pair selected");
    }
}
