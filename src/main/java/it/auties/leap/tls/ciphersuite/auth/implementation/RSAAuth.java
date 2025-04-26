package it.auties.leap.tls.ciphersuite.auth.implementation;

import it.auties.leap.tls.certificate.TlsCertificate;
import it.auties.leap.tls.ciphersuite.auth.TlsAuth;
import it.auties.leap.tls.ciphersuite.auth.TlsAuthFactory;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.util.CertificateUtils;

import java.util.List;

public final class RSAAuth implements TlsAuth {
    private static final TlsAuth INSTANCE = new RSAAuth();
    private static final TlsAuthFactory FACTORY = new TlsAuthFactory() {
        @Override
        public TlsAuth newAuth() {
            return INSTANCE;
        }

        @Override
        public boolean isAnonymous() {
            return false;
        }
    };

    private RSAAuth() {

    }

    public static TlsAuthFactory factory() {
        return FACTORY;
    }

    @Override
    public TlsCertificate validate(TlsContext context, List<TlsCertificate> certificates, List<TlsCertificate> trustAnchors) {
        var address = context.address()
                .orElse(null);
        return CertificateUtils.validateChain(address, certificates, trustAnchors, "RSA");
    }
}
