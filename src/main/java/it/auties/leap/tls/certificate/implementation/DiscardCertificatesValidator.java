package it.auties.leap.tls.certificate.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.certificate.TlsCertificate;
import it.auties.leap.tls.certificate.TlsCertificateValidator;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.context.TlsContextualProperty;

import java.util.List;

public final class DiscardCertificatesValidator implements TlsCertificateValidator {
    private static final DiscardCertificatesValidator INSTANCE = new DiscardCertificatesValidator();

    private DiscardCertificatesValidator() {

    }

    public static DiscardCertificatesValidator instance() {
        return INSTANCE;
    }

    @Override
    public TlsCertificate validate(TlsContext context, TlsSource source, List<TlsCertificate> certificates) {
        return certificates.isEmpty() ? null : certificates.getFirst();
    }
}
