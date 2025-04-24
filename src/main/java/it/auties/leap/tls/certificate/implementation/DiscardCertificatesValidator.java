package it.auties.leap.tls.certificate.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.certificate.TlsCertificate;
import it.auties.leap.tls.certificate.TlsCertificateValidator;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.property.TlsProperty;

import java.util.HexFormat;
import java.util.List;

public final class DiscardCertificatesValidator implements TlsCertificateValidator {
    private static final DiscardCertificatesValidator INSTANCE = new DiscardCertificatesValidator();

    private DiscardCertificatesValidator() {

    }

    public static DiscardCertificatesValidator instance() {
        return INSTANCE;
    }

    @Override
    public TlsCertificate validate(TlsContext context, TlsSource source, List<TlsCertificate> certificates) {
        var cipher = context.getNegotiatedValue(TlsProperty.cipher())
                .orElseThrow(() -> new TlsAlert("Missing negotiated property: cipher", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR));
        var certificate = certificates == null || certificates.isEmpty() ? null : certificates.getFirst();
        if (!cipher.authFactory().isAnonymous() && certificate == null) {
            throw new TlsAlert("Missing remote certificate with non-anonymous cipher(0x" + HexFormat.of().toHexDigits(cipher.id()) + ")", TlsAlertLevel.FATAL, TlsAlertType.NO_CERTIFICATE);
        }

        return certificate;
    }
}
