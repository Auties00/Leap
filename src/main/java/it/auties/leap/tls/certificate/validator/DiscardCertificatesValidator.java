package it.auties.leap.tls.certificate.validator;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.certificate.TlsCertificate;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.property.TlsProperty;

import java.util.HexFormat;
import java.util.List;

final class DiscardCertificatesValidator implements TlsCertificateValidator {
    static final DiscardCertificatesValidator INSTANCE = new DiscardCertificatesValidator();

    @Override
    public TlsCertificate validate(TlsContext context, TlsSource source, List<TlsCertificate> certificates) {
        var cipher = context.getNegotiatedValue(TlsProperty.cipher())
                .orElseThrow(() -> new TlsAlert("No cipher was negotiated", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR));
        var certificate = certificates == null || certificates.isEmpty() ? null : certificates.getFirst();
        if(!cipher.authFactory().isAnonymous() && certificate == null) {
            throw new TlsAlert("Missing remote certificate with non-anonymous cipher(0x" + HexFormat.of().toHexDigits(cipher.id()) + ")", TlsAlertLevel.FATAL, TlsAlertType.NO_CERTIFICATE);
        }

        return certificate;
    }
}