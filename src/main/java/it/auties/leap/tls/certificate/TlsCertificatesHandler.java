package it.auties.leap.tls.certificate;

import it.auties.leap.tls.certificate.implementation.IgnoreCertificatesHandler;
import it.auties.leap.tls.certificate.implementation.SunValidateCertificatesHandler;
import it.auties.leap.tls.context.TlsSource;

import java.net.InetSocketAddress;
import java.security.cert.X509Certificate;
import java.util.List;

public interface TlsCertificatesHandler {
    X509Certificate accept(InetSocketAddress remoteAddress, List<X509Certificate> certificates, TlsSource certificatesSource);

    static TlsCertificatesHandler validate() {
        return SunValidateCertificatesHandler.instance();
    }

    static TlsCertificatesHandler ignore() {
        return IgnoreCertificatesHandler.instance();
    }
}