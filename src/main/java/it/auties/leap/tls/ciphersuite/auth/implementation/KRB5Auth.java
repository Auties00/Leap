package it.auties.leap.tls.ciphersuite.auth.implementation;

import it.auties.leap.tls.certificate.TlsCertificate;
import it.auties.leap.tls.ciphersuite.auth.TlsAuth;
import it.auties.leap.tls.context.TlsContext;

import java.util.List;

public final class KRB5Auth implements TlsAuth {
    private static final TlsAuth INSTANCE = new KRB5Auth();

    private KRB5Auth() {

    }

    public static TlsAuth instance() {
        return INSTANCE;
    }

    @Override
    public TlsCertificate validate(TlsContext context, List<TlsCertificate> certificates, List<TlsCertificate> trustAnchors) {
        throw new UnsupportedOperationException();
    }
}
