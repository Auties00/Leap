package it.auties.leap.tls.cipher.auth.implementation;

import it.auties.leap.tls.cipher.auth.TlsAuth;
import it.auties.leap.tls.cipher.auth.TlsAuthFactory;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.util.CertificateUtils;

import java.security.cert.X509Certificate;
import java.util.List;

public final class ECDSAAuth implements TlsAuth {
    private static final TlsAuth INSTANCE = new ECDSAAuth();
    private static final TlsAuthFactory FACTORY = () -> INSTANCE;

    private ECDSAAuth() {

    }

    public static TlsAuthFactory factory() {
        return FACTORY;
    }

    @Override
    public X509Certificate validate(List<X509Certificate> certificates, TlsSource certificatesSource, TlsContext context) {
        return CertificateUtils.validateChain(context, certificatesSource, "ECDSA");
    }
}
