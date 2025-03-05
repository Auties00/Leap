package it.auties.leap.tls.cipher.auth.implementation;

import it.auties.leap.tls.cipher.auth.TlsAuth;
import it.auties.leap.tls.cipher.auth.TlsAuthFactory;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.exception.TlsException;

import java.security.cert.X509Certificate;
import java.util.List;

public final class AnonymousAuth implements TlsAuth {
    private static final TlsAuth INSTANCE = new AnonymousAuth();
    private static final TlsAuthFactory FACTORY = () -> INSTANCE;

    private AnonymousAuth() {

    }

    public static TlsAuthFactory factory() {
        return FACTORY;
    }

    @Override
    public X509Certificate validate(List<X509Certificate> certificates, TlsSource certificatesSource, TlsContext context) {
        if(!certificates.isEmpty()) {
            throw new TlsException("Anonymous auth error: expected no certificates");
        }
        return null;
    }
}
