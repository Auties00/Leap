package it.auties.leap.tls.cipher.auth;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Optional;

public interface TlsAuth {
    Optional<X509Certificate> validateFirst(List<X509Certificate> certificates);
}
