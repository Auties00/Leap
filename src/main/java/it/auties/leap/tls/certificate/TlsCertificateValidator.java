package it.auties.leap.tls.certificate;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.certificate.implementation.DiscardCertificatesValidator;
import it.auties.leap.tls.certificate.implementation.ValidateCertificatesValidator;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.util.CertificateUtils;

import java.util.List;

public interface TlsCertificateValidator {
    TlsCertificate validate(TlsContext context, TlsSource source, List<TlsCertificate> certificates);

    static TlsCertificateValidator validate() {
        return new ValidateCertificatesValidator(CertificateUtils.defaultTrustAnchors());
    }

    static TlsCertificateValidator validate(List<TlsCertificate> trustAnchors) {
        if(trustAnchors == null || trustAnchors.isEmpty()) {
            throw new TlsAlert("No trust anchors found", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
        }

        return new ValidateCertificatesValidator(trustAnchors);
    }

    static TlsCertificateValidator discard() {
        return DiscardCertificatesValidator.instance();
    }
}