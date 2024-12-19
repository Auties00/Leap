package it.auties.leap.tls.certificate;

import it.auties.leap.tls.config.TlsSource;

import java.net.InetSocketAddress;
import java.security.cert.X509Certificate;
import java.util.List;

final class TlsIgnoreCertificatesHandler implements TlsCertificatesHandler {
    static final TlsIgnoreCertificatesHandler INSTANCE = new TlsIgnoreCertificatesHandler();

    @Override
    public void accept(InetSocketAddress remoteAddress, List<X509Certificate> certificates, TlsSource certificatesSource) {

    }
}