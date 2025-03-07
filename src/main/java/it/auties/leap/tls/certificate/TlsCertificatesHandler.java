package it.auties.leap.tls.certificate;

import it.auties.leap.tls.certificate.implementation.IgnoreCertificatesHandler;
import it.auties.leap.tls.certificate.implementation.ValidateCertificatesHandler;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;

import java.security.cert.X509Certificate;
import java.util.List;

public interface TlsCertificatesHandler {
    X509Certificate validate(List<X509Certificate> certificates, TlsSource certificatesSource, TlsContext context);

    static TlsCertificatesHandler validate() {
        return ValidateCertificatesHandler.instance();
    }

    static TlsCertificatesHandler ignore() {
        return IgnoreCertificatesHandler.instance();
    }
}