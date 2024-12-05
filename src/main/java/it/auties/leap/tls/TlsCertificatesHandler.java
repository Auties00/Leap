package it.auties.leap.tls;

import it.auties.leap.tls.certificate.TlsValidateCertificatesHandler;
import it.auties.leap.tls.certificate.TlsIgnoreCertificatesHandler;

import java.net.InetSocketAddress;
import java.security.cert.X509Certificate;
import java.util.List;

@FunctionalInterface
public interface TlsCertificatesHandler {
    void accept(InetSocketAddress remoteAddress, List<X509Certificate> certificates, Source certificatesSource);

    static TlsCertificatesHandler validate() {
        return TlsValidateCertificatesHandler.INSTANCE;
    }

    static TlsCertificatesHandler ignore() {
        return TlsIgnoreCertificatesHandler.INSTANCE;
    }

    enum Source {
        SERVER,
        CLIENT
    }
}
