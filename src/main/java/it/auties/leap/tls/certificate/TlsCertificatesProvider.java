package it.auties.leap.tls.certificate;

import java.net.InetSocketAddress;
import java.security.cert.X509Certificate;
import java.util.List;

public interface TlsCertificatesProvider {
    List<X509Certificate> getCertificates(InetSocketAddress address);
}
