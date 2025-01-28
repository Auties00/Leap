package it.auties.leap.tls.certificate.implementation;

import it.auties.leap.tls.certificate.TlsCertificatesHandler;
import it.auties.leap.tls.TlsSource;

import java.net.InetSocketAddress;
import java.security.cert.X509Certificate;
import java.util.List;

public final class IgnoreCertificatesHandler implements TlsCertificatesHandler {
    private static final IgnoreCertificatesHandler INSTANCE = new IgnoreCertificatesHandler();

    public static IgnoreCertificatesHandler instance() {
        return INSTANCE;
    }

    @Override
    public void accept(InetSocketAddress remoteAddress, List<X509Certificate> certificates, TlsSource certificatesSource) {

    }
}