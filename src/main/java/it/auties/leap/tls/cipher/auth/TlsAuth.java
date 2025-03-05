package it.auties.leap.tls.cipher.auth;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;

import java.security.cert.X509Certificate;
import java.util.List;

public interface TlsAuth {
    X509Certificate validate(List<X509Certificate> certificates, TlsSource certificatesSource, TlsContext context);
}
