package it.auties.leap.tls.certificate;

import it.auties.leap.tls.config.TlsSource;

import java.net.InetSocketAddress;
import java.security.cert.X509Certificate;
import java.util.List;

@FunctionalInterface
public interface TlsCertificatesHandler {
    void accept(InetSocketAddress remoteAddress, List<X509Certificate> certificates, TlsSource certificatesSource);

    static TlsCertificatesHandler validate() {
        return TlsValidateCertificatesHandler.INSTANCE;
    }

    static TlsCertificatesHandler ignore() {
        return TlsIgnoreCertificatesHandler.INSTANCE;
    }
}