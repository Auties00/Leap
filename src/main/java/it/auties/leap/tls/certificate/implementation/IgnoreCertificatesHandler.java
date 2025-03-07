package it.auties.leap.tls.certificate.implementation;

import it.auties.leap.tls.certificate.TlsCertificatesHandler;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;

import java.security.cert.X509Certificate;
import java.util.List;

public final class IgnoreCertificatesHandler implements TlsCertificatesHandler {
    private static final IgnoreCertificatesHandler INSTANCE = new IgnoreCertificatesHandler();

    public static IgnoreCertificatesHandler instance() {
        return INSTANCE;
    }

    @Override
    public X509Certificate validate(List<X509Certificate> certificates, TlsSource certificatesSource, TlsContext context) {

        return certificates == null || certificates.isEmpty() ? null : certificates.getFirst();
    }
}