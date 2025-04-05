package it.auties.leap.tls.certificate;

import it.auties.leap.tls.alert.TlsAlert;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Optional;

public final class TlsCertificate {
    private final TlsClientCertificateType type;
    private final X509Certificate value;
    private final PrivateKey key;

    private TlsCertificate(TlsClientCertificateType type, X509Certificate value, PrivateKey key) {
        this.type = type;
        this.value = value;
        this.key = key;
    }

    public static TlsCertificate of(TlsClientCertificateType type, X509Certificate value) {
        return of(type, value, null);
    }

    public static TlsCertificate of(TlsClientCertificateType type, X509Certificate value, PrivateKey key) {
        if(!type.accepts(value)) {
           throw new TlsAlert("Certificate type " + type + " does not accept certificate with signature " + value.getSigAlgName() + "(" + value.getSigAlgOID() + ")");
        }

        return new TlsCertificate(type, value, key);
    }

    public TlsClientCertificateType type() {
        return type;
    }

    public X509Certificate value() {
        return value;
    }

    public Optional<PrivateKey> key() {
        return Optional.ofNullable(key);
    }
}
