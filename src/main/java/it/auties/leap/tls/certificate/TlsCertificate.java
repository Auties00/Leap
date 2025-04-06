package it.auties.leap.tls.certificate;

import java.io.InputStream;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Objects;
import java.util.Optional;

// TODO: Rewrite certificate parsing to be more efficient
public final class TlsCertificate {
    private final X509Certificate value;
    private final byte[] encoded;
    private final PrivateKey key;

    private TlsCertificate(X509Certificate value, PrivateKey key) {
        this.value = value;
        try {
            this.encoded = value.getEncoded();
        } catch (CertificateEncodingException e) {
            throw new RuntimeException(e);
        }
        this.key = key;
    }

    public static TlsCertificate of(X509Certificate value, PrivateKey key) {
        if(key == null) {
            throw new IllegalArgumentException("key cannot be null");
        }

        return new TlsCertificate(value, key);
    }

    public static TlsCertificate of(X509Certificate value) {
        return new TlsCertificate(value, null);
    }

    public static TlsCertificate of(InputStream value) {
        try {
            var factory = CertificateFactory.getInstance("X.509");
            var certificate = (X509Certificate) factory.generateCertificate(value);
            return new TlsCertificate(certificate, null);
        }catch (CertificateException exception) {
            throw new RuntimeException(exception);
        }
    }

    public X509Certificate value() {
        return value;
    }

    public int length() {
        return encoded.length;
    }

    public byte[] encoded() {
        return encoded;
    }

    public Optional<PrivateKey> key() {
        return Optional.ofNullable(key);
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof TlsCertificate that
                && Objects.equals(value, that.value);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(value);
    }
}
