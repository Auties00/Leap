package it.auties.leap.tls.certificate;

import it.auties.leap.tls.TlsCertificatesHandler;

import java.net.InetSocketAddress;
import java.security.cert.X509Certificate;
import java.util.List;

public final class TlsIgnoreCertificatesHandler implements TlsCertificatesHandler {
    public static final TlsIgnoreCertificatesHandler INSTANCE = new TlsIgnoreCertificatesHandler();

    @Override
    public void accept(InetSocketAddress remoteAddress, List<X509Certificate> certificates, Source certificatesSource) {

    }
}
