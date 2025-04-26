package it.auties.leap.tls.ciphersuite.auth.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.certificate.TlsCertificate;
import it.auties.leap.tls.ciphersuite.auth.TlsAuth;
import it.auties.leap.tls.ciphersuite.auth.TlsAuthFactory;
import it.auties.leap.tls.context.TlsContext;

import java.util.List;

public final class AnonymousAuth implements TlsAuth {
    private static final TlsAuth INSTANCE = new AnonymousAuth();
    private static final TlsAuthFactory FACTORY = new TlsAuthFactory() {
        @Override
        public TlsAuth newAuth() {
            return INSTANCE;
        }

        @Override
        public boolean isAnonymous() {
            return true;
        }
    };

    private AnonymousAuth() {

    }

    public static TlsAuthFactory factory() {
        return FACTORY;
    }

    @Override
    public TlsCertificate validate(TlsContext context, List<TlsCertificate> certificates, List<TlsCertificate> trustAnchors) {
        if(certificates != null && !certificates.isEmpty()) {
            throw new TlsAlert("Anonymous auth error: expected no certificates", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
        }

        return null;
    }
}
