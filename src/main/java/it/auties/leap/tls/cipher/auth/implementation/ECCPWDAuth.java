package it.auties.leap.tls.cipher.auth.implementation;

import it.auties.leap.tls.cipher.auth.TlsAuth;
import it.auties.leap.tls.cipher.auth.TlsAuthFactory;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Optional;

public final class ECCPWDAuth implements TlsAuth {
    private ECCPWDAuth() {
    }

    private static final TlsAuth INSTANCE = new ECCPWDAuth();
    private static final TlsAuthFactory FACTORY = () -> INSTANCE;

    public static TlsAuthFactory factory() {
        return FACTORY;
    }

    @Override
    public X509Certificate validate(List<X509Certificate> certificates, TlsSource certificatesSource, TlsContext context) {
        throw new UnsupportedOperationException();
    }
}
