package it.auties.leap.tls.certificate;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.extension.TlsExtension;

import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;

import static it.auties.leap.tls.util.BufferUtils.*;

// TODO: Rewrite certificate parsing to be more efficient
public final class TlsCertificate {
    private final X509Certificate value;
    private final byte[] encoded;
    private final PrivateKey privateKey;
    private final List<TlsExtension> extensions;

    private TlsCertificate(X509Certificate value, PrivateKey privateKey) {
        this.value = value;
        try {
            this.encoded = value.getEncoded();
        } catch (CertificateEncodingException e) {
            throw new RuntimeException(e);
        }
        this.privateKey = privateKey;
        this.extensions = new ArrayList<>();
    }

    public static TlsCertificate of(X509Certificate value, PrivateKey privateKey) {
        return new TlsCertificate(value, privateKey);
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
            throw new TlsAlert(
                    "Cannot parse certificate: " + exception.getMessage(),
                    TlsAlertLevel.FATAL,
                    TlsAlertType.BAD_CERTIFICATE
            );
        }
    }

    public X509Certificate value() {
        return value;
    }

    public PublicKey publicKey() {
        return value.getPublicKey();
    }

    public Optional<PrivateKey> privateKey() {
        return Optional.ofNullable(privateKey);
    }

    public boolean hasExtensions() {
        return !extensions.isEmpty();
    }

    public List<TlsExtension> extensions() {
        return Collections.unmodifiableList(extensions);
    }

    public void addExtension(TlsExtension extension) {
        if(extension != null) {
            extensions.add(extension);
        }
    }

    public void addExtensions(Collection<? extends TlsExtension> extensions) {
        if(extensions != null) {
            this.extensions.addAll(extensions);
        }
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

    public void serialize(ByteBuffer buffer) {
        writeBytesBigEndian24(buffer, encoded);
        for (var extension : extensions) {
            extension.toPayload().serializePayload(buffer);
        }
    }

    public int length() {
        return INT24_LENGTH + encoded.length;
    }
}
