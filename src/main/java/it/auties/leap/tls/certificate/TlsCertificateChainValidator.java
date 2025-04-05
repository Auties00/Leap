package it.auties.leap.tls.certificate;

import it.auties.leap.tls.certificate.implementation.DiscardCertificatesValidator;
import it.auties.leap.tls.certificate.implementation.ValidateCertificatesValidator;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;

import java.security.cert.X509Certificate;
import java.util.List;

public interface TlsCertificateChainValidator {
    X509Certificate validate(TlsContext context, TlsSource source, List<X509Certificate> certificates);

    static TlsCertificateChainValidator validate() {
        return ValidateCertificatesValidator.instance();
    }

    static TlsCertificateChainValidator discard() {
        return DiscardCertificatesValidator.instance();
    }
}