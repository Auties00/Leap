package it.auties.leap.tls.certificate;

import it.auties.leap.tls.context.TlsContext;

import java.security.cert.X509Certificate;
import java.util.List;

public interface TlsCertificatesSupplier {
    List<X509Certificate> get(TlsContext context);
}
