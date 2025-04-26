package it.auties.leap.tls.ciphersuite.auth;

import it.auties.leap.tls.certificate.TlsCertificate;
import it.auties.leap.tls.context.TlsContext;

import java.util.List;

public interface TlsAuth {
    TlsCertificate validate(TlsContext context, List<TlsCertificate> certificates, List<TlsCertificate> trustAnchors);
}
