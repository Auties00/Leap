package it.auties.leap.tls.certificate.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.certificate.TlsCertificatesConsumer;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.property.TlsProperty;

import java.security.cert.X509Certificate;
import java.util.List;

public final class ValidateCertificatesConsumer implements TlsCertificatesConsumer {
    private static final ValidateCertificatesConsumer INSTANCE = new ValidateCertificatesConsumer();

    public static ValidateCertificatesConsumer instance() {
        return INSTANCE;
    }

    private ValidateCertificatesConsumer() {

    }

    @Override
    public X509Certificate validate(List<X509Certificate> certificates, TlsSource source, TlsContext context) {
        if(certificates == null || certificates.isEmpty()) {
            throw new TlsAlert("Cannot validate X509 certificates: no certificates found");
        }

        return context.getNegotiatedValue(TlsProperty.cipher())
                .orElseThrow(() -> TlsAlert.noNegotiatedProperty(TlsProperty.cipher()))
                .authFactory()
                .newAuth()
                .validate(context, source, certificates);
    }
}
