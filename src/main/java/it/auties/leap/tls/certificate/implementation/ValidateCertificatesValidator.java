package it.auties.leap.tls.certificate.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.certificate.TlsCertificateChainValidator;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.property.TlsProperty;

import java.security.cert.X509Certificate;
import java.util.List;

public final class ValidateCertificatesValidator implements TlsCertificateChainValidator {
    private static final ValidateCertificatesValidator INSTANCE = new ValidateCertificatesValidator();

    public static ValidateCertificatesValidator instance() {
        return INSTANCE;
    }

    private ValidateCertificatesValidator() {

    }

    @Override
    public X509Certificate validate(TlsContext context, TlsSource source, List<X509Certificate> certificates) {
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
