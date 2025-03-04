package it.auties.leap.tls.cipher.auth.implementation;

import it.auties.leap.tls.cipher.auth.TlsAuth;
import it.auties.leap.tls.cipher.auth.TlsAuthFactory;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Optional;

public final class PSKAuth implements TlsAuth {
    private static final TlsAuth INSTANCE = new PSKAuth();
    private static final TlsAuthFactory FACTORY = () -> INSTANCE;

    private PSKAuth() {

    }

    public static TlsAuthFactory factory() {
        return FACTORY;
    }

    @Override
    public Optional<X509Certificate> validateFirst(List<X509Certificate> certificates) {
        throw new UnsupportedOperationException();
    }
}
