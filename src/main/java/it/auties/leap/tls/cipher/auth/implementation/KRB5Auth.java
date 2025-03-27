package it.auties.leap.tls.cipher.auth.implementation;

import it.auties.leap.tls.cipher.auth.TlsAuth;
import it.auties.leap.tls.cipher.auth.TlsAuthFactory;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;

import java.security.cert.X509Certificate;
import java.util.List;

public final class KRB5Auth implements TlsAuth {
    private static final TlsAuth INSTANCE = new KRB5Auth();
    private static final TlsAuthFactory FACTORY = () -> INSTANCE;

    private KRB5Auth() {

    }

    public static TlsAuthFactory factory() {
        return FACTORY;
    }

    @Override
    public X509Certificate validate(TlsContext context, TlsSource certificatesSource, List<X509Certificate> certificates) {
        throw new UnsupportedOperationException();
    }
}
