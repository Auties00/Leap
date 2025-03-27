package it.auties.leap.tls.cipher.auth.implementation;

import it.auties.leap.tls.cipher.auth.TlsAuth;
import it.auties.leap.tls.cipher.auth.TlsAuthFactory;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;

import java.security.cert.X509Certificate;
import java.util.List;

// TODO: Implement TLS 1.3 Any auth
public final class ContextualAuth implements TlsAuth {
    private static final TlsAuth INSTANCE = new ContextualAuth();
    private static final TlsAuthFactory FACTORY = () -> INSTANCE;

    private ContextualAuth() {

    }

    public static TlsAuthFactory factory() {
        return FACTORY;
    }

    @Override
    public X509Certificate validate(TlsContext context, TlsSource certificatesSource, List<X509Certificate> certificates) {
        throw new UnsupportedOperationException();
    }
}
