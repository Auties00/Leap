package it.auties.leap.tls.certificate.implementation;

import it.auties.leap.tls.alert.TlsAlert;
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
        if(certificates == null || certificates.isEmpty()) {
            throw new TlsAlert("Cannot validate X509 certificates: no certificates found");
        }

        return context.getNegotiatedValue(TlsProperty.cipher())
                .orElseThrow(() -> TlsAlert.noNegotiatedProperty(TlsProperty.cipher()))
                .authFactory()
                .newAuth()
                .validate(context, certificates, trustAnchors);
    }
}
