package it.auties.leap.tls.certificate.implementation;

import it.auties.leap.tls.certificate.TlsCertificatesConsumer;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;

import java.security.cert.X509Certificate;
import java.util.List;

public final class IgnoreCertificatesConsumer implements TlsCertificatesConsumer {
    private static final IgnoreCertificatesConsumer INSTANCE = new IgnoreCertificatesConsumer();

    public static IgnoreCertificatesConsumer instance() {
        return INSTANCE;
    }

    @Override
    public X509Certificate validate(List<X509Certificate> certificates, TlsSource source, TlsContext context) {
        return certificates == null || certificates.isEmpty() ? null : certificates.getFirst();
    }
}