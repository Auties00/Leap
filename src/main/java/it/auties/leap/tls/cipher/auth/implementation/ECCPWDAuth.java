package it.auties.leap.tls.cipher.auth.implementation;

import it.auties.leap.tls.cipher.auth.TlsAuth;
import it.auties.leap.tls.cipher.auth.TlsAuthFactory;
import it.auties.leap.tls.TlsContext;
import it.auties.leap.tls.TlsSource;

import java.security.cert.X509Certificate;
import java.util.List;

public final class ECCPWDAuth implements TlsAuth {
    private ECCPWDAuth() {
    }

    private static final TlsAuth INSTANCE = new ECCPWDAuth();
    private static final TlsAuthFactory FACTORY = () -> INSTANCE;

    public static TlsAuthFactory factory() {
        return FACTORY;
    }

    @Override
    public X509Certificate validate(TlsContext context, TlsSource certificatesSource, List<X509Certificate> certificates) {
        throw new UnsupportedOperationException();
    }
}
