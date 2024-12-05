package it.auties.leap.tls;

import java.net.InetSocketAddress;
import java.security.cert.X509Certificate;
import java.util.List;

@FunctionalInterface
public interface TlsCertificatesProvider {
    List<X509Certificate> getCertificates(InetSocketAddress address);
}
