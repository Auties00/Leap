package it.auties.leap.tls.certificate.validator;

import it.auties.leap.tls.certificate.TlsCertificate;
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
        return new ValidateCertificatesValidator(trustAnchors);
    }

    static TlsCertificateValidator discard() {
        return DiscardCertificatesValidator.INSTANCE;
    }
}