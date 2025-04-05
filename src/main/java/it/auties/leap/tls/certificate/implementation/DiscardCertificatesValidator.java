package it.auties.leap.tls.certificate.implementation;

import it.auties.leap.tls.certificate.TlsCertificateChainValidator;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;

import java.security.cert.X509Certificate;
import java.util.List;

public final class DiscardCertificatesValidator implements TlsCertificateChainValidator {
    private static final DiscardCertificatesValidator INSTANCE = new DiscardCertificatesValidator();

    public static DiscardCertificatesValidator instance() {
        return INSTANCE;
    }

    @Override
    public X509Certificate validate(TlsContext context, TlsSource source, List<X509Certificate> certificates) {
        return certificates == null || certificates.isEmpty() ? null : certificates.getFirst();
    }
}