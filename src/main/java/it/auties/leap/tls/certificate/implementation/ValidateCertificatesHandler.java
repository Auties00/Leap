package it.auties.leap.tls.certificate.implementation;

import it.auties.leap.tls.certificate.TlsCertificatesHandler;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.exception.TlsException;

import java.security.cert.X509Certificate;
import java.util.List;

public final class ValidateCertificatesHandler implements TlsCertificatesHandler {
    private static final ValidateCertificatesHandler INSTANCE = new ValidateCertificatesHandler();

    public static ValidateCertificatesHandler instance() {
        return INSTANCE;
    }

    private ValidateCertificatesHandler() {

    }

    @Override
    public X509Certificate validate(List<X509Certificate> certificates, TlsSource certificatesSource, TlsContext context) {
        if(certificates == null || certificates.isEmpty()) {
            throw new TlsException("Cannot validate X509 certificates: no certificates found");
        }

        return context.negotiatedCipher()
                .orElseThrow(() -> new TlsException("No cipher was negotiated yet"))
                .authFactory()
                .newAuth()
                .validate(certificates, certificatesSource, context);
    }
}
