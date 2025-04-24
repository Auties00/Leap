package it.auties.leap.tls.certificate.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.certificate.TlsCertificate;
import it.auties.leap.tls.certificate.TlsCertificateValidator;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.property.TlsProperty;

import java.util.List;

public final class ValidateCertificatesValidator implements TlsCertificateValidator {
    private final List<TlsCertificate> trustAnchors;

    public ValidateCertificatesValidator(List<TlsCertificate> trustAnchors) {
        this.trustAnchors = trustAnchors;
    }

    @Override
    public TlsCertificate validate(TlsContext context, TlsSource source, List<TlsCertificate> certificates) {
        return context.getNegotiatedValue(TlsProperty.cipher())
                .orElseThrow(() -> new TlsAlert("Missing negotiated property: cipher", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR))
                .authFactory()
                .newAuth()
                .validate(context, certificates, trustAnchors);
    }
}
