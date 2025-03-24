package it.auties.leap.tls.cipher.auth;

import it.auties.leap.tls.TlsContext;
import it.auties.leap.tls.TlsSource;

import java.security.cert.X509Certificate;
import java.util.List;

public interface TlsAuth {
    X509Certificate validate(TlsContext context, TlsSource certificatesSource, List<X509Certificate> certificates);
}
