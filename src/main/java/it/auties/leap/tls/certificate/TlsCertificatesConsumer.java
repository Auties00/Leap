package it.auties.leap.tls.certificate;

import it.auties.leap.tls.certificate.implementation.IgnoreCertificatesConsumer;
import it.auties.leap.tls.certificate.implementation.ValidateCertificatesConsumer;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;

import java.security.cert.X509Certificate;
import java.util.List;

public interface TlsCertificatesConsumer {
    X509Certificate validate(List<X509Certificate> certificates, TlsSource source, TlsContext context);

    static TlsCertificatesConsumer validate() {
        return ValidateCertificatesConsumer.instance();
    }

    static TlsCertificatesConsumer discard() {
        return IgnoreCertificatesConsumer.instance();
    }
}