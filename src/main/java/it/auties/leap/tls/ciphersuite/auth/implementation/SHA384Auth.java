package it.auties.leap.tls.ciphersuite.auth.implementation;

import it.auties.leap.tls.certificate.TlsCertificate;
import it.auties.leap.tls.ciphersuite.auth.TlsAuth;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.util.CertificateUtils;

import java.util.List;

public final class SHA384Auth implements TlsAuth {
    private static final TlsAuth INSTANCE = new SHA384Auth();

    private SHA384Auth() {

    }

    public static TlsAuth instance() {
        return INSTANCE;
    }

    @Override
    public TlsCertificate validate(TlsContext context, List<TlsCertificate> certificates, List<TlsCertificate> trustAnchors) {
        return CertificateUtils.validateChain(
                context.address().orElse(null),
                certificates,
                trustAnchors,
                "SHA384"
        );
    }
}
