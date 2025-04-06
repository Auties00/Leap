package it.auties.leap.tls.certificate.implementation;

import it.auties.leap.tls.certificate.TlsCertificate;
import it.auties.leap.tls.certificate.TlsCertificateValidator;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;

import java.util.List;

public final class DiscardCertificatesValidator implements TlsCertificateValidator {
    private static final DiscardCertificatesValidator INSTANCE = new DiscardCertificatesValidator();

    public static DiscardCertificatesValidator instance() {
        return INSTANCE;
    }

    @Override
    public TlsCertificate validate(TlsContext context, TlsSource source, List<TlsCertificate> certificates) {
        return certificates == null || certificates.isEmpty() ? null : certificates.getFirst();
    }
}